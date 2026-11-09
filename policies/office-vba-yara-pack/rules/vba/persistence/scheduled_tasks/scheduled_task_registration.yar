rule Office_VBA_ScheduledTaskRegistration : vba persistence
{
    meta:
        id = "OFM-VBA-1104"
        description = "Scheduled task creation through schtasks command text or Task Scheduler COM."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "persistence"
        subcategory = "scheduled_tasks"
        severity = "high"
        confidence = "medium"
        false_positive = "Approved management macros may register scheduled jobs."
        attack = "T1053.005"

    strings:
        $tool = /\bschtasks(\.exe)?[ \t]+[^\r\n"]{0,120}\/create\b/ ascii wide nocase
        $com = "Schedule.Service" ascii wide nocase
        $register = /\.[ \t]*RegisterTask(Definition)?\b/ ascii wide nocase

    condition:
        $tool or ($com and $register)
}
