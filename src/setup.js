import { fileURLToPath } from 'node:url';

const quoteShell = value => "'" + value.replaceAll("'", "'\\''") + "'";
export function connectionSetup({ nodePath = process.execPath, scriptPath = fileURLToPath(new URL('./cli.js', import.meta.url)), stateDir } = {}) {
  const env = stateDir ? { AWS_MCP_STATE_DIR: stateDir } : undefined;
  const json = JSON.stringify({ mcpServers: { aws_approval: { command: nodePath, args: [scriptPath, 'mcp'], ...(env ? { env } : {}) } } }, null, 2);
  const codex = ['[mcp_servers.aws_approval]', `command = ${JSON.stringify(nodePath)}`, `args = [${JSON.stringify(scriptPath)}, "mcp"]`, 'startup_timeout_sec = 20', 'tool_timeout_sec = 900', ...(stateDir ? ['', '[mcp_servers.aws_approval.env]', `AWS_MCP_STATE_DIR = ${JSON.stringify(stateDir)}`] : [])].join('\n');
  const claude = ['claude mcp add --transport stdio', ...(stateDir ? ['--env', quoteShell(`AWS_MCP_STATE_DIR=${stateDir}`)] : []), 'aws_approval --', quoteShell(nodePath), quoteShell(scriptPath), 'mcp'].join(' ');
  return { clients: [
    { id: 'codex', name: 'Codex', location: 'Add this entry to ~/.codex/config.toml.', label: 'config.toml', code: codex, note: 'Merge with existing settings. Restart Codex or reconnect the server from its MCP settings.', docs: 'https://learn.chatgpt.com/docs/extend/mcp' },
    { id: 'claude-code', name: 'Claude Code', location: 'Run this command in your project terminal.', label: 'Terminal', code: claude, note: 'Open Claude Code in that project. Run /mcp to check that aws_approval is connected. For short tool timeouts, ask it to use request_aws and poll get_aws_request.', docs: 'https://code.claude.com/docs/en/mcp' },
    { id: 'claude-desktop', name: 'Claude Desktop', location: 'Open Settings → Developer → Edit Config. Merge this server into claude_desktop_config.json.', label: 'claude_desktop_config.json', code: json, note: 'Fully quit and reopen Claude Desktop. If a tool call times out while you are reviewing, use request_aws and poll get_aws_request.', docs: 'https://modelcontextprotocol.io/docs/develop/connect-local-servers' },
    { id: 'cursor', name: 'Cursor', location: 'Add this to .cursor/mcp.json in your project, or ~/.cursor/mcp.json for all projects.', label: 'mcp.json', code: json, note: 'Merge with any existing mcpServers entries. Enable aws_approval in Cursor’s MCP settings, then start a new agent chat.', docs: 'https://cursor.com/docs/mcp' },
  ] };
}
