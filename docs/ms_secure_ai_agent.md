# Secure AI at scale

## Notes
- 

### Session 1- Containing your AI insider by Jimena De Uria
- AI insider risk
- AI Agent
    - Polymorphic, can change behaviour, not deterministic, resource driven to get the results
    - collabroate with other agents and applications
- Layers - Multi layer containment strategy at MS
    - Identity
    - Permissions
    - Data
    - Endpoint
    - Network
    - Cloud
    - Runtime (VM, OS, Browser)
- Discover every agent
    - Needs sensor to discover and identify all agents in the environment
    - Create an agent identity- identity does not live with the agent.
    - Contain network access, limit API calls, Tool, MCP calls, data requests, etc.
    - Enforce information flow controls- what data are going in and out, trusted vs untrusted, various levels of sensitivity
    - 
- New cyber stack
    - Agents, harness, models
      ^
      |
    - Contexts (provide right correct)
      ^
      |
    - Signals, sensors, actuators
- Project Perception (Team of guardian agents)
    - Red team
    - Blue team
    - Green team - fix and remediate

### Session - 2 - Securing AI adopting at Scale

- Entra GSA
- Identity and Access
- Australia ISM
- User =# Agent
- Design Time control (maxi time the agent can assume) =# Runtime security 

- Discovery --> Onboarding and Lifecycle --> Runtime controls
- Access package - assign API permission (Design time control vs runtime permission) API calls and MCP tools
    - At run time, agent will have subset of the permissions based on the job
- Home --> Settings --> policy tempalte - policy -> Access Package --> Assign it to the agent
    - Design Time control
    - What happens at Run time -have subset of the permissions from design time
        - User 
    - Run time - short term token, entraID will define/ create a new access token and assign
        - who do you assign the permission to
        - 
- network, identity, data, endpoint
- Entra Defined Object
- An Object ID in Microsoft Entra ID (formerly Azure Active Directory) is a unique, permanent 36-character GUID (Globally Unique Identifier) that identifies a specific directory object—such as a user, group, application, or service principal—within your tenant
- Common 
- Ownership and life cycle management
    - every agent has a sponsor/ owner
    - Sponsor assignned to every agent created.
    - Procurement Agent
- power platform admin center
- Copilot studio does sass
- Foundry MCP protection


- Virtual ID (Object ID) - instance of agent running on the device
- Type - claude code
- Do not allow claude code in the environment - needs to block Type
- ATID - Agent Type ID

- Intune policy - for local agent deployment?
- 

## References
- Object ID, https://learn.microsoft.com/en-us/entra/identity/hybrid/cloud-sync/concept-attributes
- Agent identity sponsor tasks in Lifecycle Workflows, https://learn.microsoft.com/en-us/entra/id-governance/agent-sponsor-tasks
- Global Secure Access, https://learn.microsoft.com/en-us/entra/global-secure-access/overview-what-is-global-secure-access
- AI agent runtime protection with Microsoft Defender for Endpoint (Preview), https://learn.microsoft.com/en-us/defender-endpoint/ai-agent-runtime-protection-overview
- The Microsoft AI and Agent Platform — Securing and Governing Intelligent Agents, https://techcommunity.microsoft.com/blog/microsoft-security-blog/the-microsoft-ai-and-agent-platform-%E2%80%94-securing-and-governing-intelligent-agents/4562204
- Overview of the Power Platform admin center, https://learn.microsoft.com/en-us/power-platform/admin/admin-documentation

- Foundry MCP Server best practices and security guidance, 
- Secure a Model Context Protocol (MCP) server with Microsoft Entra ID, https://learn.microsoft.com/en-us/entra/agent-id/secure-mcp-server-with-entra-id


### Secureing the Agentic Workforce with Agent 365
- Ana-Gabriela Hernandez, Deepika Mahankali, Senior Data Security Solutions Engineer (Purview)- how those extend to agents
- Models + Tools + Network + Agents + Apps + Data + Containers - 
- Agent 365, https://learn.microsoft.com/en-us/microsoft-agent-365/overview
- Microsoft 365 admin center
    - Management
        - Agents, MCP servers, Plugins, Skills, Connectors, Shadow tools
        - Agent Registry
    - Governance
    - Security
    - Business Value
- https://learn.microsoft.com/en-us/microsoft-agent-365/admin/agent-365-overview

##