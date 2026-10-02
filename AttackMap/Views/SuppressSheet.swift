import SwiftUI

/// What the Findings detail needs to offer "Suppress…": where the entry goes
/// and how to rescan afterwards. `nil` (e.g. a fleet view) hides the action.
struct SuppressContext {
    /// The suppress file the entry is appended to (shown in the sheet).
    let targetURL: URL
    /// "Ignore all suppressions" is on, so a rescan won't apply the entry.
    let suppressionsIgnored: Bool
    let canRescan: Bool
    let rescan: @MainActor () -> Void
}

/// Builds one `.attackmap-suppress.yaml` entry for a finding and appends it,
/// only when the user presses "Add suppression". The target path is always
/// visible, since this writes into the user's repository.
struct SuppressSheet: View {
    let finding: Finding
    let context: SuppressContext
    @Environment(\.dismiss) private var dismiss

    enum Scope: Hashable { case thisFinding, wholeRule }

    @State private var scope: Scope = .wholeRule
    @State private var reason = ""
    @State private var pathsText = ""
    @State private var hasExpiry = false
    @State private var expires = Calendar.current.date(byAdding: .day, value: 90, to: Date()) ?? Date()
    @State private var owner = ""
    @State private var ticket = ""
    @State private var error: String?
    @State private var written = false

    private var idUsable: Bool {
        (try? SuppressFileWriter.validate(SuppressRule(selector: .id(finding.id), reason: "x"))) != nil
    }

    private var rule: SuppressRule {
        SuppressRule(
            selector: scope == .thisFinding ? .id(finding.id) : .rule(finding.effectiveRuleId),
            reason: reason,
            paths: scope == .wholeRule ? pathsText.split(separator: ",").map(String.init) : [],
            expires: hasExpiry ? expires : nil,
            owner: owner,
            ticket: ticket)
    }

    private var preview: String {
        var r = rule
        if r.reason.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { r.reason = "…" }
        return SuppressFileWriter.entryLines(r, indent: 0).joined(separator: "\n")
    }

    private var targetExists: Bool { FileManager.default.fileExists(atPath: context.targetURL.path) }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Suppress finding").font(.title3.weight(.semibold))
            Text(finding.title).foregroundStyle(.secondary).lineLimit(2)

            if written { doneView } else { form }
        }
        .padding(20)
        .frame(width: 520)
    }

    @ViewBuilder private var form: some View {
        Form {
            Picker("Suppress", selection: $scope) {
                Text("Every “\(finding.effectiveRuleId)” finding").tag(Scope.wholeRule)
                Text("Only this finding (id \(finding.id))").tag(Scope.thisFinding)
                    .disabled(!idUsable)
            }
            .pickerStyle(.radioGroup)

            if scope == .wholeRule {
                HStack {
                    TextField("Limit to paths", text: $pathsText, prompt: Text("optional, e.g. tests/fixtures/**, vendor/*"))
                    if !finding.locationFiles.isEmpty {
                        Button("Use finding's files") {
                            pathsText = finding.locationFiles.joined(separator: ", ")
                        }
                        .help(finding.locationFiles.joined(separator: "\n"))
                    }
                }
            }

            TextField("Reason", text: $reason, prompt: Text("required — why this is accepted"), axis: .vertical)
                .lineLimit(1...3)

            Toggle("Expires", isOn: $hasExpiry)
            if hasExpiry {
                DatePicker("On", selection: $expires, in: Date()..., displayedComponents: .date)
            }
            TextField("Owner", text: $owner, prompt: Text("optional, e.g. platform-team"))
            TextField("Ticket", text: $ticket, prompt: Text("optional, e.g. SEC-123 or a URL"))
        }
        .formStyle(.grouped)
        .frame(maxHeight: 360)

        VStack(alignment: .leading, spacing: 4) {
            Text(targetExists ? "Appends to" : "Creates")
                .font(.caption.weight(.semibold)).foregroundStyle(.secondary)
            Text(context.targetURL.path)
                .font(.caption.monospaced()).textSelection(.enabled)
            Text(preview)
                .font(.caption.monospaced()).foregroundStyle(.secondary)
                .padding(8)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 6))
        }

        if let error {
            Label(error, systemImage: "exclamationmark.triangle.fill")
                .font(.callout).foregroundStyle(.orange)
        }

        HStack {
            Spacer()
            Button("Cancel", role: .cancel) { dismiss() }
                .keyboardShortcut(.cancelAction)
            Button("Add suppression") { save() }
                .keyboardShortcut(.defaultAction)
                .disabled(reason.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
        }
    }

    @ViewBuilder private var doneView: some View {
        Label("Added to \(context.targetURL.lastPathComponent)", systemImage: "checkmark.circle.fill")
            .foregroundStyle(.green)
        Text(context.targetURL.path).font(.caption.monospaced()).foregroundStyle(.secondary)
            .textSelection(.enabled)
        if context.suppressionsIgnored {
            Label("“Ignore all suppressions” is on, so a rescan won't apply this. Turn it off in the Suppress menu first.",
                  systemImage: "exclamationmark.triangle")
                .font(.callout).foregroundStyle(.orange)
        } else {
            Text("Rescan to apply it — the finding then moves to the Suppressed list.")
                .font(.callout).foregroundStyle(.secondary)
        }
        HStack {
            Button("Reveal in Finder") { ReportExporter.reveal(context.targetURL) }
            Spacer()
            Button("Done") { dismiss() }
                .keyboardShortcut(.cancelAction)
            Button("Rescan now") {
                dismiss()
                context.rescan()
            }
            .keyboardShortcut(.defaultAction)
            .disabled(!context.canRescan)
        }
    }

    private func save() {
        do {
            try SuppressFileWriter.append(rule, to: context.targetURL)
            error = nil
            written = true
        } catch {
            self.error = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
        }
    }
}
