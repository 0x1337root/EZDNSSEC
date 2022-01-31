<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:template match="/">
<html>
<body>
<h1 align="center">DMARC REPORT</h1>

<table border="3" align="center" >
<tr>
	<th>Organization Name</th>
	<th>Email</th>
	<th>Report ID</th>
	<th>Date Begin</th>
	<th>Date End</th>
</tr>
<xsl:for-each select="feedback">
<tr>
	<td><xsl:value-of select="report_metadata/org_name"/></td>
	<td><xsl:value-of select="report_metadata/email"/></td>
	<td><xsl:value-of select="report_metadata/report_id"/></td>
	<td><xsl:value-of select="report_metadata/date_range/begin"/></td>
	<td><xsl:value-of select="report_metadata/date_range/end"/></td>
</tr>
	</xsl:for-each>
	</table>

<br><br></br></br>

<table border="3" align="center" >
<tr>
	<th>Policy Published Domain</th>
	<th>ADKIM</th>
	<th>ASPF</th>
	<th>P</th>
	<th>SP</th>
	<th>PCT</th>
</tr>
<xsl:for-each select="feedback">
<tr>
	<td><xsl:value-of select="policy_published/domain"/></td>
	<td><xsl:value-of select="policy_published/adkim"/></td>
	<td><xsl:value-of select="policy_published/aspf"/></td>
	<td><xsl:value-of select="policy_published/p"/></td>
	<td><xsl:value-of select="policy_published/sp"/></td>
	<td><xsl:value-of select="policy_published/pct"/></td>
</tr>
	</xsl:for-each>
	</table>

<br><br></br></br>

<table border="3" align="center" >
<tr>
	<th>Source IP</th>
	<th>Count</th>
	<th>Disposition</th>
	<th>DKIM</th>
	<th>SPF</th>
	<th>Header From</th>
	<th>SPF Domain</th>
	<th>SPF Result</th>
	<th>DKIM Domain</th>
	<th>DKIM Result</th>
</tr>
	<xsl:for-each select="feedback/record">
<tr>
	<td><xsl:value-of select="row/source_ip"/></td>
	<td><xsl:value-of select="row/count"/></td>
	<td><xsl:value-of select="row/policy_evaluated/disposition"/></td>
	<td><xsl:value-of select="row/policy_evaluated/dkim"/></td>
	<td><xsl:value-of select="row/policy_evaluated/spf"/></td>
	<td><xsl:value-of select="identifiers/header_from"/></td>
	<td><xsl:value-of select="auth_results/spf/domain"/></td>
	<td><xsl:value-of select="auth_results/spf/result"/></td>
	<td><xsl:value-of select="auth_results/dkim/domain"/></td>
	<td><xsl:value-of select="auth_results/dkim/result"/></td>
</tr>
	</xsl:for-each>
	</table>
</body>
</html>
</xsl:template>
</xsl:stylesheet>
