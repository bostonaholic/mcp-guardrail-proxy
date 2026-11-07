// Drives one app window through the macOS Accessibility API, by process id. It reads and acts on
// the web page inside a WKWebView, where each element with an HTML id carries it as
// AXDOMIdentifier. It moves no mouse and types no keys, so it leaves the user's screen alone.
//
// Usage: ax-driver <pid> <command> [args]
//   wait-ready [seconds]   Exit 0 once the page's web area exists, 1 at the timeout (default 20).
//   window-id              Print the CGWindowID of the app's titled on-screen window.
//   dump                  Print the window's element tree, one element per line.
//   get <selector>         Print a JSON object: found, enabled, value, text.
//   set <selector> <text>  Set a text field's value.
//   press <selector>       Press a button, checkbox, or disclosure triangle.
//
// A selector is "#id" for an HTML id, or "AXRole:Title" such as "AXDisclosureTriangle:Settings".
// An element whose HTML has the `hidden` attribute is absent, so `get` prints found=false.
// Exit codes: 0 ok; 1 not found, not ready, or the action failed; 2 bad usage or no permission.

import ApplicationServices
import Foundation

func fail(_ message: String, _ code: Int32 = 1) -> Never {
  FileHandle.standardError.write(("ax-driver: " + message + "\n").data(using: .utf8)!)
  exit(code)
}

let args = CommandLine.arguments
guard args.count >= 3, let pid = pid_t(args[1]) else {
  fail("usage: ax-driver <pid> wait-ready|dump|get|set|press [args]", 2)
}
guard AXIsProcessTrusted() else {
  fail("this process lacks Accessibility permission (System Settings > Privacy & Security > Accessibility)", 2)
}

let app = AXUIElementCreateApplication(pid)
// WebKit builds the page's accessibility tree only for a client that asks for it.
AXUIElementSetAttributeValue(app, "AXManualAccessibility" as CFString, kCFBooleanTrue)

func attribute(_ element: AXUIElement, _ name: String) -> AnyObject? {
  var value: AnyObject?
  AXUIElementCopyAttributeValue(element, name as CFString, &value)
  return value
}

func string(_ element: AXUIElement, _ name: String) -> String {
  guard let value = attribute(element, name) else { return "" }
  return value as? String ?? "\(value)"
}

func children(_ element: AXUIElement) -> [AXUIElement] {
  attribute(element, "AXChildren") as? [AXUIElement] ?? []
}

func windows() -> [AXUIElement] {
  attribute(app, "AXWindows") as? [AXUIElement] ?? []
}

func walk(_ element: AXUIElement, depth: Int = 0, visit: (AXUIElement, Int) -> Bool) -> Bool {
  if visit(element, depth) { return true }
  for child in children(element) where walk(child, depth: depth + 1, visit: visit) { return true }
  return false
}

func matches(_ element: AXUIElement, _ selector: String) -> Bool {
  if selector.hasPrefix("#") {
    return string(element, "AXDOMIdentifier") == String(selector.dropFirst())
  }
  let parts = selector.split(separator: ":", maxSplits: 1).map(String.init)
  guard parts.count == 2 else { fail("bad selector \(selector); use #id or AXRole:Title", 2) }
  return string(element, "AXRole") == parts[0] && string(element, "AXTitle") == parts[1]
}

func find(_ selector: String) -> AXUIElement? {
  var found: AXUIElement?
  for window in windows() {
    if walk(window, visit: { element, _ in
      if matches(element, selector) { found = element; return true }
      return false
    }) { break }
  }
  return found
}

func text(_ element: AXUIElement) -> String {
  var pieces: [String] = []
  _ = walk(element) { child, _ in
    if string(child, "AXRole") == "AXStaticText" { pieces.append(string(child, "AXValue")) }
    return false
  }
  return pieces.joined(separator: " ")
}

func hasWebArea() -> Bool {
  windows().contains { window in walk(window) { element, _ in string(element, "AXRole") == "AXWebArea" } }
}

func printJSON(_ object: [String: Any]) {
  let data = try! JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
  print(String(data: data, encoding: .utf8)!)
}

switch args[2] {
case "wait-ready":
  let seconds = args.count > 3 ? Double(args[3]) ?? 20 : 20
  let deadline = Date().addingTimeInterval(seconds)
  while Date() < deadline {
    if hasWebArea() { exit(0) }
    usleep(250_000)
  }
  fail("no web area after \(Int(seconds)) seconds; the page did not load")
case "window-id":
  let list = CGWindowListCopyWindowInfo([.optionOnScreenOnly], kCGNullWindowID) as? [[String: Any]] ?? []
  let window = list.first { info in
    (info[kCGWindowOwnerPID as String] as? Int) == Int(pid)
      && !((info[kCGWindowName as String] as? String) ?? "").isEmpty
  }
  guard let id = window?[kCGWindowNumber as String] else { fail("no on-screen window for pid \(pid)") }
  print(id)
case "dump":
  for window in windows() {
    _ = walk(window) { element, depth in
      let fields = ["AXRole", "AXDOMIdentifier", "AXTitle", "AXValue", "AXEnabled"].compactMap { name -> String? in
        let value = string(element, name)
        return value.isEmpty ? nil : "\(name.dropFirst(2))=\(value)"
      }
      print(String(repeating: "  ", count: depth) + fields.joined(separator: " "))
      return false
    }
  }
case "get":
  guard args.count == 4 else { fail("usage: ax-driver <pid> get <selector>", 2) }
  guard let element = find(args[3]) else {
    printJSON(["found": false])
    exit(0)
  }
  printJSON([
    "found": true,
    "enabled": (attribute(element, "AXEnabled") as? Bool) ?? true,
    "value": string(element, "AXValue"),
    "text": text(element),
  ])
case "set":
  guard args.count == 5 else { fail("usage: ax-driver <pid> set <selector> <text>", 2) }
  guard let element = find(args[3]) else { fail("no element matches \(args[3])") }
  AXUIElementSetAttributeValue(element, "AXFocused" as CFString, kCFBooleanTrue)
  let status = AXUIElementSetAttributeValue(element, "AXValue" as CFString, args[4] as CFString)
  guard status == .success, string(element, "AXValue") == args[4] else {
    fail("could not set \(args[3]) (AXError \(status.rawValue)); is it disabled?")
  }
case "press":
  guard args.count == 4 else { fail("usage: ax-driver <pid> press <selector>", 2) }
  guard let element = find(args[3]) else { fail("no element matches \(args[3])") }
  var actions: CFArray?
  AXUIElementCopyActionNames(element, &actions)
  if ((actions as? [String]) ?? []).contains(kAXPressAction) {
    let status = AXUIElementPerformAction(element, kAXPressAction as CFString)
    guard status == .success else { fail("could not press \(args[3]) (AXError \(status.rawValue))") }
  } else {
    // A <summary> offers no AXPress. Focus it and send Space to this process only.
    AXUIElementSetAttributeValue(element, "AXFocused" as CFString, kCFBooleanTrue)
    for down in [true, false] {
      CGEvent(keyboardEventSource: nil, virtualKey: 49, keyDown: down)!.postToPid(pid)
      usleep(50_000)
    }
  }
  usleep(300_000)
default:
  fail("unknown command \(args[2])", 2)
}
