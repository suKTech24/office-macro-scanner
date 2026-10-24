Attribute VB_Name = "ModGst"
Option Explicit

' Clean test sample: Australian GST (10%) helpers. Shows a message and does calculations. Nothing else.
Public Sub ShowGstExample()
    MsgBox "A $100.00 price excluding GST is " & Format(priceIncludingGst(100), "$0.00") & " including GST."
End Sub

' GST-exclusive price -> GST-inclusive price. =PriceIncludingGst(100) gives 110.
Public Function priceIncludingGst(ByVal priceExcludingGst As Double, _
                                  Optional ByVal gstRate As Double = 0.1) As Double
    priceIncludingGst = Round(priceExcludingGst * (1 + gstRate), 2)
End Function

' GST contained in a GST-inclusive price (one eleventh at 10%). =GstIncludedInPrice(110) gives 10.
Public Function GstIncludedInPrice(ByVal priceIncludingGst As Double, _
                                   Optional ByVal gstRate As Double = 0.1) As Double
    GstIncludedInPrice = Round(priceIncludingGst * gstRate / (1 + gstRate), 2)
End Function



