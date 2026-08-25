//! Bounded native-only discovery for Chrome's remote-debugging consent sheet.
//!
//! Consent discovery must not reuse the ordinary snapshot walker. That walker
//! intentionally enables and materializes Chromium web accessibility, and a
//! cancelled `spawn_blocking` walk can continue traversing a large page after
//! the browser connection has already won its race.

use std::time::{Duration, Instant};

use core_foundation::base::{CFEqual, CFRelease, CFRetain, CFTypeRef};

use super::bindings::*;
use super::tree::AXNode;
use super::window_scope::{decide_window_scope, ScopeDecision, TopLevelCandidate, WindowScope};

const CONSENT_AX_MESSAGING_TIMEOUT_SECONDS: f32 = 0.1;
const CONSENT_SCAN_WALL_TIME: Duration = Duration::from_millis(400);
const CONSENT_MAX_SHALLOW_CHILDREN: usize = 128;

#[derive(Debug)]
pub(crate) struct NativeConsentSheetWalk {
    pub(crate) nodes: Vec<AXNode>,
    pub(crate) truncated: bool,
    pub(crate) window_scope: Option<WindowScope>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NativeScanTarget {
    Sheet(usize),
    Window(usize),
}

fn native_scan_targets(
    candidates: &[TopLevelCandidate],
    decision: &ScopeDecision,
    approved_window_id: u32,
) -> Vec<NativeScanTarget> {
    if !decision.scope.is_matched() {
        return Vec::new();
    }
    decision
        .walk
        .iter()
        .filter_map(|&index| {
            let candidate = &candidates[index];
            if candidate.role == "AXSheet" {
                Some(NativeScanTarget::Sheet(index))
            } else if candidate.role == "AXWindow"
                && candidate.ax_window_id == Some(approved_window_id)
            {
                Some(NativeScanTarget::Window(index))
            } else {
                None
            }
        })
        .collect()
}

fn is_web_content_role(role: &str) -> bool {
    let normalized = role
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect::<String>();
    normalized.contains("webarea")
        || normalized.contains("documentweb")
        || matches!(normalized.as_str(), "document" | "axdocument")
}

unsafe fn set_consent_messaging_timeout(element: AXUIElementRef) {
    let _ = AXUIElementSetMessagingTimeout(element, CONSENT_AX_MESSAGING_TIMEOUT_SECONDS);
}

unsafe fn push_unique_owned_root(roots: &mut Vec<AXUIElementRef>, owned_root: AXUIElementRef) {
    if roots
        .iter()
        .any(|&root| CFEqual(root as CFTypeRef, owned_root as CFTypeRef) != 0)
    {
        CFRelease(owned_root as CFTypeRef);
    } else {
        roots.push(owned_root);
    }
}

unsafe fn collect_direct_sheet_children(
    window: AXUIElementRef,
    roots: &mut Vec<AXUIElementRef>,
    truncated: &mut bool,
    deadline: Instant,
) {
    set_consent_messaging_timeout(window);
    let children = copy_children(window);
    for (index, child) in children.into_iter().enumerate() {
        if index >= CONSENT_MAX_SHALLOW_CHILDREN || Instant::now() >= deadline {
            *truncated = true;
            CFRelease(child as CFTypeRef);
            continue;
        }
        set_consent_messaging_timeout(child);
        if copy_string_attr(child, "AXRole").as_deref() == Some("AXSheet") {
            // Transfer the retain from copy_children into the roots collection.
            push_unique_owned_root(roots, child);
        } else {
            // In particular, never recurse into AXWebArea / AXDocumentWeb.
            CFRelease(child as CFTypeRef);
        }
    }
}

#[allow(clippy::too_many_arguments)]
unsafe fn walk_sheet_element(
    element: AXUIElementRef,
    depth: usize,
    nodes: &mut Vec<AXNode>,
    counter: &mut usize,
    visited: &mut usize,
    truncated: &mut bool,
    max_elements: usize,
    max_depth: usize,
    deadline: Instant,
) {
    if Instant::now() >= deadline || *visited >= max_elements {
        *truncated = true;
        return;
    }
    *visited += 1;

    set_consent_messaging_timeout(element);
    let role = copy_string_attr(element, "AXRole").unwrap_or_else(|| "AXUnknown".to_owned());
    if is_web_content_role(&role) {
        return;
    }

    let title = copy_string_attr(element, "AXTitle")
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    let value = copy_string_attr(element, "AXValue")
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    let description = copy_string_attr(element, "AXDescription")
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    let identifier = copy_string_attr(element, "AXIdentifier")
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    let help = copy_string_attr(element, "AXHelp")
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    let actions = copy_action_names(element);
    let element_index = if actions.is_empty() {
        None
    } else {
        let index = *counter;
        *counter += 1;
        CFRetain(element as CFTypeRef);
        Some(index)
    };
    nodes.push(AXNode {
        element_index,
        role,
        title,
        value,
        description,
        identifier,
        help,
        actions,
        element_ptr: element as usize,
        depth,
        parent_element_index: None,
        frame: None,
        value_state: None,
        value_description: None,
        min_value: None,
        max_value: None,
        enabled: None,
        selected: None,
        in_web_content: false,
    });

    let children = copy_children(element);
    if depth >= max_depth {
        if !children.is_empty() {
            *truncated = true;
        }
        for child in children {
            CFRelease(child as CFTypeRef);
        }
        return;
    }
    for child in children {
        walk_sheet_element(
            child,
            depth + 1,
            nodes,
            counter,
            visited,
            truncated,
            max_elements,
            max_depth,
            deadline,
        );
        CFRelease(child as CFTypeRef);
    }
}

/// Inspect only native Chrome sheet surfaces for the exact approved process
/// and window. This deliberately does not call `ensure_chromium_ax_enabled`
/// and never walks an ordinary browser window or web-document subtree.
pub(crate) fn walk_native_consent_sheets_bounded(
    pid: i32,
    approved_window_id: u32,
    max_elements: usize,
    max_depth: usize,
) -> NativeConsentSheetWalk {
    let deadline = Instant::now() + CONSENT_SCAN_WALL_TIME;
    let mut nodes = Vec::new();
    let mut truncated = false;
    let window_scope;

    unsafe {
        let app = AXUIElementCreateApplication(pid);
        if app.is_null() {
            return NativeConsentSheetWalk {
                nodes,
                truncated,
                window_scope: Some(WindowScope::AxUnresolved { ax_window_count: 0 }),
            };
        }
        set_consent_messaging_timeout(app);

        let mut top_level = copy_children(app);
        for window in copy_ax_windows(app) {
            if top_level
                .iter()
                .any(|&candidate| CFEqual(candidate as CFTypeRef, window as CFTypeRef) != 0)
            {
                CFRelease(window as CFTypeRef);
            } else {
                top_level.push(window);
            }
        }

        let candidates = top_level
            .iter()
            .map(|&element| {
                set_consent_messaging_timeout(element);
                let role = copy_string_attr(element, "AXRole").unwrap_or_default();
                TopLevelCandidate {
                    subrole: (role == "AXWindow")
                        .then(|| copy_string_attr(element, "AXSubrole"))
                        .flatten(),
                    identifier: copy_string_attr(element, "AXIdentifier"),
                    ax_window_id: (role == "AXWindow")
                        .then(|| ax_get_window_id(element))
                        .flatten(),
                    role,
                }
            })
            .collect::<Vec<_>>();
        let decision = decide_window_scope(&candidates, approved_window_id, || {
            crate::windows::resolve_window_owner(pid, approved_window_id)
        });
        window_scope = Some(decision.scope.clone());

        let mut roots = Vec::new();
        for target in native_scan_targets(&candidates, &decision, approved_window_id) {
            if Instant::now() >= deadline {
                truncated = true;
                break;
            }
            match target {
                NativeScanTarget::Sheet(index) => {
                    let root = top_level[index];
                    CFRetain(root as CFTypeRef);
                    push_unique_owned_root(&mut roots, root);
                }
                NativeScanTarget::Window(index) => collect_direct_sheet_children(
                    top_level[index],
                    &mut roots,
                    &mut truncated,
                    deadline,
                ),
            }
        }

        for element in top_level {
            CFRelease(element as CFTypeRef);
        }
        CFRelease(app as CFTypeRef);

        let mut counter = 0;
        let mut visited = 0;
        for root in roots {
            walk_sheet_element(
                root,
                0,
                &mut nodes,
                &mut counter,
                &mut visited,
                &mut truncated,
                max_elements,
                max_depth,
                deadline,
            );
            CFRelease(root as CFTypeRef);
        }
    }

    NativeConsentSheetWalk {
        nodes,
        truncated,
        window_scope,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_targets_only_exact_window_and_native_sheet_siblings() {
        let candidates = [
            TopLevelCandidate::new("AXMenuBar", None),
            TopLevelCandidate::new("AXWebArea", None),
            TopLevelCandidate::new("AXSheet", None),
            TopLevelCandidate::new("AXWindow", Some(11)),
            TopLevelCandidate::new("AXWindow", Some(22)),
        ];
        let decision = ScopeDecision {
            scope: WindowScope::Matched,
            walk: vec![0, 1, 2, 4],
        };
        assert_eq!(
            native_scan_targets(&candidates, &decision, 22),
            vec![NativeScanTarget::Sheet(2), NativeScanTarget::Window(4)]
        );
    }

    #[test]
    fn unresolved_scope_has_no_scan_targets() {
        let candidates = [
            TopLevelCandidate::new("AXSheet", None),
            TopLevelCandidate::new("AXWindow", Some(11)),
        ];
        let decision = ScopeDecision {
            scope: WindowScope::AxUnresolved { ax_window_count: 1 },
            walk: Vec::new(),
        };
        assert!(native_scan_targets(&candidates, &decision, 22).is_empty());
    }

    #[test]
    fn web_document_roles_are_pruned_from_consent_discovery() {
        for role in ["AXWebArea", "AXDocumentWeb", "document", "AXDocument"] {
            assert!(is_web_content_role(role), "{role} must be pruned");
        }
        for role in ["AXSheet", "AXButton", "AXGroup"] {
            assert!(!is_web_content_role(role), "{role} remains native");
        }
    }
}
