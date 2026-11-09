rule Office_VBA_PowerPointAndOutlookEvents : vba auto_execution
{
    meta:
        id = "OFM-VBA-0104"
        description = "PowerPoint presentation-open or Outlook startup event declaration."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "auto_execution"
        subcategory = "office_events"
        severity = "info"
        confidence = "medium"
        false_positive = "Office add-ins can register normal startup routines."

    strings:
        $entry = /\bsub[ \t]+(Application_Startup|[a-z_][a-z0-9_]{0,40}_PresentationOpen|SlideShowBegin)[ \t]*\(/ ascii wide nocase

    condition:
        $entry
}
