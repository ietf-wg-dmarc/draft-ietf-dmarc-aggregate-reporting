%%%

	Title = "Domain-based Message Authentication, Reporting, and Conformance (DMARC) Aggregate Reporting"
	abbrev = "DMARC Aggregate Reporting"
	docName = "draft-ietf-dmarc-aggregate-reporting-24"
	category = "std"
	obsoletes = [7489]
	ipr = "trust200902"
	area = "Application"
	workgroup = "DMARC"
	submissiontype = "IETF"
	keyword = [""]

	date = "2024-12-16T00:00:00Z"

	[seriesInfo]
	name = "Internet-Draft"
	value = "draft-ietf-dmarc-aggregate-reporting-24"
	stream = "IETF"
	status = "standard"

	[[author]]
	initials = "A."
	surname = "Brotman (ed)"
	fullname = "Alex Brotman"
	organization = "Comcast, Inc."
	  [author.address]
	  email = "alex_brotman@comcast.com"

%%%

.# Abstract

Domain-based Message Authentication, Reporting, and Conformance
(DMARC) allows for Domain Owners to request aggregate reports from receivers.
This report is an XML document, and contains extensible elements that allow for 
other types of data to be specified later.  The aggregate reports can be
submitted to the Domain Owner's specified destination as supported by the
receiver.

{mainmatter}

# Introduction

A key component of DMARC [@!I-D.ietf-dmarc-dmarcbis] is the ability for Domain Owners to 
request that receivers provide various types of reports.  These reports allow 
Domain Owners to have insight into which IP addresses are sending on their 
behalf, and some insight into whether or not the volume may be legitimate.  
These reports expose information relating to the DMARC policy, as well as 
the outcome of SPF [@!RFC7208] & DKIM [@!RFC6376] validation.

There are a number of terms defined in [@!I-D.ietf-dmarc-dmarcbis] that are used
within this document.  Understanding those definitions will aid in reading
this document.

## Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL
NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED",
"MAY", and "OPTIONAL" in this document are to be interpreted as
described in BCP 14 [@!RFC2119] [@!RFC8174] when, and only when, they
appear in all capitals, as shown here.

# DMARC Feedback

Providing Domain Owners with visibility into how Mail Receivers implement
and enforce the DMARC mechanism in the form of feedback is critical to
establishing and maintaining accurate authentication deployments.  When
Domain Owners can see what effect their policies and practices are having,
they are better willing and able to use quarantine and reject policies.


## Aggregate Reports

The DMARC aggregate feedback report is designed to provide Domain
Owners with precise insight into:

*  authentication results,
*  corrective action that needs to be taken by Domain Owners, and
*  the effect of Domain Owner DMARC policy on email streams processed
   by Mail Receivers.

Aggregate DMARC feedback provides visibility into real-world email
streams that Domain Owners need in order to make informed decisions 
regarding the publication of a DMARC policy.  When Domain Owners know what
legitimate mail they are sending, what the authentication results are
on that mail, and what forged mail receivers are getting, they can
make better decisions about the policies they need and the steps they
need to take to enable those policies.  When Domain Owners set
policies appropriately and understand their effects, Mail Receivers
can act on them confidently.

Visibility comes in the form of daily (or more frequent) Mail
Receiver-originated feedback reports that contain aggregate data on
message streams relevant to the Domain Owner.  This information
includes data about messages that passed DMARC authentication as well
as those that did not.

A separate report **MUST** be generated for each Policy Domain encountered
during the reporting period. See below for further explanation in "Handling 
Domains in Reports".

The report may include the following data:

*  The DMARC policy discovered and applied, if any
*  The selected message disposition
*  The identifier evaluated by SPF and the SPF result, if any
*  The identifier evaluated by DKIM and the DKIM result, if any
*  For both DKIM and SPF, an indication of whether the identifier was
   in DMARC alignment (see [@I-D.ietf-dmarc-dmarcbis, section 3.2.7])
*  Sending and receiving domains
*  The number of successful authentications
*  The counts of messages based on all messages received, even if
   their delivery is ultimately blocked by other filtering agents.

The format for these reports is defined in Appendix A, as well as the possible
values for some of the elements below.  Most of these values have a definition
tied to [@!I-D.ietf-dmarc-dmarcbis].

DMARC Aggregate Reports MUST contain two primary sections ("metadata" & "data"
below) ; one consisting of descriptive information (with two elements), 
and the other a set of IP address-focused row-based data.  Each report MUST 
contain data for only one Policy Domain. A single report MUST contain data 
for one policy configuration.  If multiple configurations were observed 
during a single reporting period, a reporting entity MAY choose to send 
multiple reports, otherwise the reporting entity SHOULD note only the final 
configuration observed during the period. See below for further information.

The informative section MUST contain two elements.  One will be the metadata 
section which MUST contain the fields related to "org_name", "email",
"report_id", and "date_range". Optional fields MAY include 
"extra_contact_info", an "error" field.  The "date_range" field will 
contain "begin" and "end" fields as epoch timestamps. The other element will 
be the "policy_published", which will record the policy configuration observed by 
the receiving system.  Mandatory fields are "domain", "p", "sp". Optional 
fields are "fo", "adkim", "aspf", "testing", and "discovery_method".  There 
is be an optional third section, "extension".

Within the data section, the report will contain record(s) stating which
IP addresses were seen to have delivered messages for the Author Domain to the receiving
system.  For each IP address that is being reported, there will be at least one "record" element.
Each "record" element will have one "row", one "identifiers", and one "auth_results" 
sub-element.  Within the "row" element, there MUST be "source_ip" and "count".
There MUST also exist a "policy_evaluated", with sub-elements of "disposition",
"dkim", and "spf".  There MAY be an element for "reason", meant to include 
any notes the reporter might want to include as to why the "disposition" policy
does not match the "policy_published", such as a Local Policy override (See 
Section 2.1.5, Policy Override Reason).  The "dkim" and "spf" elements MUST be the 
evaluated values as they relate to DMARC, not the values the receiver may 
have used when overriding the policy.  Within the "identifiers" element, there 
MUST exist the data that was used to apply policy for the given IP address. 
There MUST be a "header_from" element, which will contain the RFC5322.From 
domain from the message.  There MAY be an optional "envelope_from" element, 
which contains the RFC5321.MailFrom domain that the SPF check has been 
applied to. This element MAY be existing but empty if the message had a null 
reverse-path ([@!RFC5321], Section 4.5.5). There MAY be an optional 
"envelope_to" element, which contains the RFC5321.RcptTo (see [@!RFC5598])
domain from the message.

There MUST be an "auth_results" element within the "record" element.  This will
contain the data related to authenticating the messages associated with this sending
IP address. There MAY be a number of optional "dkim" sub-elements, one for 
each checked DKIM  signature.  There MAY be an optional "spf" sub-element.  
These elements MUST have a "domain" that was used during validation, as well as 
"result". If validation is attempted for any DKIM signature, the results MUST 
be included in the report (within reason, see "DKIM Signatures in Aggregate 
Reports" below for handling numerous signatures).  The "dkim" element MUST 
include a "selector" element that was observed during validation. For the 
"spf" element, the "result" element MUST contain a lower-case string where 
the value is one of the results defined in [@!RFC8601] Section 2.7.2.  The 
"dkim" result MUST contain a lower-case string where the value is one of 
the results defined in [@!RFC8601] Section 2.7.1. Both the "spf" and "dkim" 
results may optionally include a "human_result" element meant for the report
to convey more descriptive information back to the Domain Owner relating to
evaluation failures. There is an optional section for extensions.

### Handling Domains in Reports

In the same report, there **MUST** be a single Policy Domain, though there could be
multiple RFC5322.From Domains.  Each RFC5322.From domain will create its own "record" 
within the report.  Consider the case where there are three domains with traffic 
volume to report: example.com, foo.example.com, and bar.example.com.  There will be 
explicit DMARC Policy Records for example.com and bar.example.com, with distinct policies.  There 
is no explicit DMARC Policy Record for foo.example.com, so it will be reliant on the 
policy described for example.com.  For a report period, there would now be two reports.  
The first will be for bar.example.com, and contain only one "record", for 
bar.example.com.  The second report would be for example.com and contain multiple 
"record" elements, one for example.com and one for foo.example.com (and extensibly, 
other "record" elements for subdomains which likewise did not have an explicit
DMARC Policy Record).

### DKIM Signatures in Aggregate Reports {#dkim-signatures}

Within a single message, the possibility exists that there could be multiple DKIM
signatures. When validation of the message occurs, some signatures may pass,
while some may not.  As these pertain to DMARC, and especially to aggregate
reporting, reporters may not find it clear which DKIM signatures they should include
in a report. Signatures, regardless of outcome, could help the report ingester
determine the source of a message. However, there is a preference as to which
signatures are included.

1. A signature that passes DKIM, in strict alignment with the RFC5322.From domain
2. A signature that passes DKIM, in relaxed alignment with the RFC5322.From domain
3. Any other DKIM signatures that pass
4. DKIM signatures that do not pass

A report **SHOULD** contain no more than 100 signatures for a given "row", in 
decreasing priority.

### Unique Identifiers in Aggregate Reporting

There are a few places where a unique identifier is specified as part of the
body of the report, the subject, and so on.  These unique identifiers should be
consistent per each report.  Specified below, the reader will see a 
"Report-ID" and "unique-id".  These are the fields that **MUST** be identical when used.

### Error element {#error}

A few examples of information contained within the "error" element(s):

* DMARC Policy Record evaluation errors (invalid "rua" or "sp", etc.)
* Multiple DMARC Policy Records at a given location

Be mindful that the "error" element is an unbounded string, but should not contain
an extremely large body.  Provide enough information to assist the Domain Owner
with understanding some issues with their authentication or DMARC Policy Record.

### Policy Override Reason {#policy-override-reason}

The "reason" element, indicating an override of the DMARC policy, consists of a 
mandatory "type" element and an optional "comment" element. The "type" element
**MUST** have one of the pre-defined values listed below. The "comment" element
is an unbounded string for providing further details.

Possible values for the policy override type:

"local_policy": The Mail Receiver's local policy exempted the message
     from being subjected to the Domain Owner's requested policy
     action.

"mailing_list": Local heuristics determined that the message arrived
     via a mailing list, and thus authentication of the original
     message was not expected to succeed.

"other": Some policy exception not covered by the other entries in
     this list occurred.  Additional detail can be found in the
     "comment" element.

"policy_test_mode": The message was exempted from application of policy by
     the testing mode ("t" tag) in the DMARC Policy Record.

"trusted_forwarder": Message authentication failure was anticipated by
     other evidence linking the message to a locally maintained list of
     known and trusted forwarders.

## Extensions

The document format supports optional elements for extensions.
The absence or existence of this section **SHOULD NOT** create an error when 
processing reports. This will be covered in a separate section.

## Changes in Policy During Reporting Period

Note that Domain Owners or their agents may change the published
DMARC Policy Record for a domain or subdomain at any time.  From a Mail
Receiver's perspective, this will occur during a reporting period and
may be noticed during that period, at the end of that period when
reports are generated, or during a subsequent reporting period, all
depending on the Mail Receiver's implementation.  Under these
conditions, it is possible that a Mail Receiver could do any of the
following:

*  generate for such a reporting period a single aggregate report
   that includes message dispositions based on the old policy, or a
   mix of the two policies, even though the report only contains a
   single "policy_published" element;
*  generate multiple reports for the same period, one for each
   published policy occurring during the reporting period;

Such policy changes are expected to be infrequent for any given
domain, whereas more stringent policy monitoring requirements on the
Mail Receiver would produce a very large burden at Internet scale.
Therefore, it is the responsibility of Report Consumers (i.e., vendors)
and Domain Owners to be aware of this situation and expect such mixed 
reports during the propagation of the new policy to Mail Receivers.

## Report Request Discovery

A Mail Receiver discovers reporting requests when it looks up a DMARC
Policy Record that corresponds to an RFC5322.From domain on received
mail.  The presence of the "rua" tag specifies where to send
feedback.

## Transport

The Mail Receiver, after preparing a report, **MUST** evaluate the
provided reporting URIs (See [@!I-D.ietf-dmarc-dmarcbis]) in the order 
given.  Any reporting URI that includes a size limitation exceeded by 
the generated report (after compression and after any encoding required 
by the particular transport mechanism) **MUST NOT** be used.  An attempt
**MUST** be made to deliver an aggregate report to every remaining URI, up
to the Receiver's limits on supported URIs.

If transport is not possible because the services advertised by the
published URIs are not able to accept reports (e.g., the URI refers
to a service that is unreachable, or all provided URIs specify size
limits exceeded by the generated record), the Mail Receiver **MAY** 
send a short report indicating that a report is available but could 
not be sent.  The Mail Receiver **MAY** cache that data and try again 
later, or **MAY** discard data that could not be sent.

Where the URI specified in a "rua" tag does not specify otherwise, a
Mail Receiver generating a feedback report **SHOULD** employ a secure
transport mechanism.

### Definition of Report-ID {#report-id}

This identifier **MUST** be unique among reports to the same domain to
aid receivers in identifying duplicate reports should they happen.
The Report-ID value should be constructed using the following ABNF:

~~~
  ridfmt =  (dot-atom-text ["@" dot-atom-text]) ; from RFC5322

  ridtxt =  ("<" ridfmt ">") / ridfmt
~~~

The format specified here is not very strict as the key goal is uniqueness.

### Email

The message generated by the Mail Receiver **MUST** be a [@!RFC5322] message
formatted per [@!RFC2045].  The aggregate report itself **MUST** be included
in one of the parts of the message, as an attachment with a corresponding
media type from below.  A human-readable annotation **MAY** be included as a body 
part (with a human-friendly content-type, such as "text/plain" or 
"text/html").

The aggregate data **MUST** be an XML file that **SHOULD** be subjected to
GZIP [@!RFC1952] compression.  Declining to apply compression can cause the
report to be too large for a receiver to process (the total message size
could exceed the receiver SMTP size limit); doing the compression increases 
the chances of acceptance of the report at some compute cost.  The
aggregate data **MUST** be present using the media type "application/gzip" if
compressed (see [@!RFC6713]), and "text/xml" otherwise.  The attachment
filename **MUST** be constructed using the following ABNF:

~~~
  filename = receiver "!" policy-domain "!" begin-timestamp
             "!" end-timestamp [ "!" unique-id ] "." extension

  receiver = domain
             ; imported from [@!RFC5322]

  policy-domain   = domain

  begin-timestamp = 1*DIGIT
                    ; seconds since 00:00:00 UTC January 1, 1970
                    ; indicating start of the time range contained
                    ; in the report

  end-timestamp = 1*DIGIT
                  ; seconds since 00:00:00 UTC January 1, 1970
                  ; indicating end of the time range contained
                  ; in the report

  unique-id = 1*(ALPHA / DIGIT)

  extension = "xml" / "xml.gz"
~~~

The extension **MUST** be "xml" for a plain XML file, or "xml.gz" for an
XML file compressed using GZIP.

"unique-id" allows an optional unique ID generated by the Mail
Receiver to distinguish among multiple reports generated
simultaneously by different sources within the same Domain Owner.  A
viable option may be to explore UUIDs [@?RFC9562].

If a report generator needs to re-send a report, the system **MUST**
use the same filename as the original report.  This would
allow the receiver to overwrite the data from the original, or discard
second instance of the report.

For example, this is a sample filename for the gzip file of a
report to the Domain Owner "example.com" from the Mail Receiver
"mail.receiver.example":

  mail.receiver.example!example.com!1013662812!1013749130.xml.gz

No specific MIME message structure is required.  It is presumed that
the aggregate reporting address will be equipped to extract body
parts with the prescribed media type and filename and ignore the
rest.

Email streams carrying DMARC feedback data **MUST** conform to the DMARC
mechanism, thereby resulting in an aligned "pass" (see Section 3.1).
This practice minimizes the risk of Report Consumers processing
fraudulent reports.

The RFC5322.Subject field for individual report submissions **MUST**
conform to the following ABNF:

~~~
  dmarc-subject = %s"Report" 1*FWS %s"Domain:"
                  1*FWS domain-name 1*FWS         ; policy domain
                  %s"Submitter:" 1*FWS
                  domain-name 1*FWS               ; report generator
                  [ %s"Report-ID:" 1*FWS ridtxt ] ; defined below
~~~

The first domain-name indicates the DNS domain name about which the
report was generated.  The second domain-name indicates the DNS
domain name representing the Mail Receiver generating the report.
The purpose of the Report-ID: portion of the field is to enable the
Domain Owner to identify and ignore duplicate reports that might be
sent by a Mail Receiver.

For instance, this is a possible Subject field for a report to the
Domain Owner "example.com" from the Mail Receiver
"mail.receiver.example".  It is folded as allowed by [@!RFC5322]:

```
  Subject: Report Domain: example.com
      Submitter: mail.receiver.example
      Report-ID: <sample-ridtxt@example.com>
```

This transport mechanism potentially encounters a problem when
feedback data size exceeds maximum allowable attachment sizes for
either the generator or the consumer. 

Optionally, the report sender **MAY** choose to use the same "ridtxt"
as a part or whole of the RFC5322.Message-Id header included with the report.
Doing so may help receivers distinguish when a message is a re-transmission
or duplicate report.

### Other Methods

The specification as written allows for the addition of other
registered URI schemes to be supported in later versions.

### Handling of Duplicates

There may be a situation where the report generator attempts to deliver
duplicate information to the receiver.  This may manifest as an exact
duplicate of the report, or as duplicate information between two reports.
In these situations, the decision of how to handle the duplicate data
lies with the receiver.  As noted above, the sender **MUST** use the same
unique identifiers when sending the report.  This allows the receiver to
better understand when duplicates happen.  A few options on how to 
handle that duplicate information:

*  Reject back to sender, ideally with a permfail error noting
   the duplicate receipt
*  Discard upon receipt
*  Inspect the contents to evaluate the timestamps and reported data,
   act as appropriate
*  Accept the duplicate data

When accepting the data, that's likely in a situation where it's not
yet noticed, or a one-off experience.  Long term, duplicate data
is not ideal.  In the situation of a partial time frame overlap, there is
no clear way to distinguish the impact of the overlap.  The receiver would
need to accept or reject the duplicate data in whole.

# Verifying External Destinations

It is possible to specify destinations for the different reports that
are outside the authority of the Domain Owner making the request.
This allows domains that do not operate mail servers to request
reports and have them go someplace that is able to receive and
process them.

Without checks, this would allow a bad actor to publish a DMARC
Policy Record that requests that reports be sent to a victim address,
and then send a large volume of mail that will fail both DKIM and SPF
checks to a wide variety of destinations; the victim will in turn be
flooded with unwanted reports.  Therefore, a verification mechanism
is included.

When a Mail Receiver discovers a DMARC Policy Record in the DNS, and the
Organizational Domain at which that record was discovered is not
identical to the Organizational Domain of the host part of the
authority component of a [@!RFC3986] specified in the "rua" tag,
the following verification steps **MUST** be taken:

1.  Extract the host portion of the authority component of the URI.
    Call this the "destination host", as it refers to a Report
    Receiver.

2.  Prepend the string "_report._dmarc".

3.  Prepend the domain name from which the policy was retrieved,
    after conversion to an A-label [@!RFC5890] if needed.

4.  If the length of the constructed name exceed DNS limits,
    a positive determination of the external reporting
    relationship cannot be made; stop.

5.  Query the DNS for a TXT record at the constructed name.  If the
    result of this request is a temporary DNS error of some kind
    (e.g., a timeout), the Mail Receiver **MAY** elect to temporarily
    fail the delivery so the verification test can be repeated later.

6.  For each record returned, parse the result as a series of
    "tag=value" pairs, i.e., the same overall format as the policy
    record (see [@!I-D.ietf-dmarc-dmarcbis, section 5.4]).  In 
    particular, the "v=DMARC1" tag is mandatory and **MUST** appear
    first in the list.  Discard any that do not pass this test. A
    trailing ";" is optional.

7.  If the result includes no TXT resource records that pass basic
    parsing, a positive determination of the external reporting
    relationship cannot be made; stop.

8.  If at least one TXT resource record remains in the set after
    parsing, then the external reporting arrangement was authorized
    by the Report Consumer.

9.  If a "rua" tag is thus discovered, replace the
    corresponding value extracted from the domain's DMARC Policy
    Record with the one found in this record.  This permits the
    Report Consumer to override the report destination.  However, to
    prevent loops or indirect abuse, the overriding URI **MUST** use the
    same destination host from the first step.

For example, if the DMARC Policy Record for "blue.example.com" contained
`"rua=mailto:reports@red.example.net"`, the Organizational Domain host
extracted from the latter ("red.example.net") does not match 
"blue.example.com", so this procedure is enacted.  A TXT query for
"blue.example.com._report._dmarc.red.example.net" is issued.  If a
single reply comes back containing a tag of "v=DMARC1", then the
relationship between the two is confirmed.  Moreover,
"red.example.net" has the opportunity to override the report
destination requested by "blue.example.com" if needed.

Where the above algorithm fails to confirm that the external
reporting was authorized by the Report Consumer, the URI **MUST** be
ignored by the Mail Receiver generating the report.  Further, if the
confirming record includes a URI whose host is again different than
the domain publishing that override, the Mail Receiver generating the
report **MUST NOT** generate a report to either the original or the
override URI.
A Report Consumer publishes such a record in its DNS if it wishes to
receive reports for other domains.

A Report Consumer that is willing to receive reports for any domain
can use a wildcard DNS record.  For example, a TXT resource record at
"*._report._dmarc.example.com" containing at least "v=DMARC1"
confirms that example.com is willing to receive DMARC reports for any
domain.

If the Report Consumer is overcome by volume, it can simply remove
the confirming DNS record.  However, due to positive caching, the
change could take as long as the time-to-live (TTL) on the record to
go into effect.

# Extensible Reporting

DMARC reports allow for some extensibility, as defined by future
documents that utilize DMARC as a foundation.  These extensions
**MUST** be properly formatted XML and meant to exist within the structure
of a DMARC report.  Two positions of type "<any>" are provided in the
existing DMARC structure, one at file level, in an "<extension>" element
after "<policy_published>" and one at record level, after "<auth_results>".
In either case, the extensions **MUST** contain a URI to the definition of
the extension so that the receiver understands how to interpret the data.

At file level:
```xml
<feedback xmlns="urn:ietf:params:xml:ns:dmarc-2.0"
          xmlns:ext="URI for an extension-supplied name space">
  ...
  <policy_published>
    <domain>example.com</domain>
    <p>quarantine</p>
    <sp>none</sp>
    <testing>n</testing>
  </policy_published>
  <extension>
    <ext:arc-override>never</ext:arc-override>
  </extension>
```

Within the "record" element:
```xml
  <record>
    <row>
       ...
    </row>
    <identifiers>
       ...
    </identifiers>
    <auth_results>
       ...
    </auth_results>
    <ext:arc-results>
       ...
    </ext:arc-results>
  </record>
  <record>
     ...
```

Here "arc-override" and "arc-results" are hypothetical element names
defined in the extension's name space.

Extension elements are optional.  Any number of extensions is allowed.
If a processor is unable to handle an extension in a report, it **SHOULD**
ignore the data and continue to the next extension.


# IANA Considerations

This document uses URNs to describe XML namespaces and XML schemas
conforming to a registry mechanism described in [@!RFC3688].  Two URI
assignments will be registered by the IANA.

## Registration request for the DMARC namespace:

URI: urn:ietf:params:xml:ns:dmarc-2.0

Registrant Contact: See the "Author's Address" section of this document.

XML: None.  Namespace URIs do not represent an XML specification.

## Registration request for the DMARC XML schema:

URI: urn:ietf:params:xml:schema:dmarc-2.0

Registrant Contact: See the "Author's Address" section of this document.

XML: See Appendix A. DMARC XML Schema in this document.


# Privacy Considerations

This section will discuss exposure related to DMARC aggregate reporting.

## Report Recipients

A DMARC Policy Record can specify that reports should be sent to an
intermediary operating on behalf of the Domain Owner.  This is done
when the Domain Owner contracts with an entity to monitor mail
streams for abuse and performance issues.  Receipt by third parties
of such data may or may not be permitted by the Mail Receiver's
privacy policy, terms of use, or other similar governing document.
Domain Owners and Mail Receivers should both review and understand if
their own internal policies constrain the use and transmission of
DMARC reporting.

Some potential exists for report recipients to perform traffic
analysis, making it possible to obtain metadata about the Receiver's
traffic.  In addition to verifying compliance with policies,
Receivers need to consider that before sending reports to a third
party.

## Data Contained Within Reports

Aggregate feedback reports contain aggregated data relating to 
messages purportedly originating from the Domain Owner. The data 
does not contain any identifying characteristics about individual 
users. No personal information such as individual email addresses, 
IP addresses of individuals, or the content of any messages, is 
included in reports.

Mail Receivers should have no concerns in sending reports as they 
do not contain personal information. In all cases, the data within 
the reports relates to the domain-level authentication information 
provided by mail servers sending messages on behalf of the Domain 
Owner. This information is necessary to assist Domain Owners in 
implementing and maintaining DMARC.

Domain Owners should have no concerns in receiving reports as 
they do not contain personal information. The reports only contain 
aggregated data related to the domain-level authentication details 
of messages claiming to originate from their domain. This information 
is essential for the proper implementation and operation of DMARC. 
Domain Owners who are unable to receive reports for organizational 
reasons, can choose to exclusively direct the reports to an 
external processor.  

## Feedback Leakage {#leakage}

Providing feedback reporting to PSOs for a PSD [@?I-D.ietf-dmarc-dmarcbis] can, in 
some cases, cause information to leak out of an organization to 
the PSO.  This leakage could potentially be utilized as part of a 
program of pervasive surveillance (see [@?RFC7624]]).  There are 
roughly three cases to consider:

* Single Organization PSDs (e.g., ".mil")

    Aggregate reports based on PSD DMARC have the potential to
    contain information about emails related to entities managed by
    the organization.  Since both the PSO and the Organizational
    Domain Owners are common, there is no additional privacy risk for
    either normal or non-existent domain reporting due to PSD DMARC.

* Multi-organization PSDs requiring DMARC usage (e.g., ".bank")

    Aggregate reports based on PSD DMARC will only be generated for domains that
    do not publish a DMARC Policy Record at the Organizational Domain or host level.
    For domains that do publish the required DMARC Policy Records, the
    feedback reporting addresses of the Organizational Domain (or
    hosts) will be used.  The only direct risk of feedback leakage for
    these PSDs are for Organizational Domains that are out of
    compliance with PSD policy.  Data on non-existent domains
    would be sent to the PSO.

* Multi-organization PSDs not requiring DMARC usage (e.g., ".com")

    Privacy risks for Organizational Domains that have not deployed DMARC
    within such PSDs can be significant.  For non-DMARC Organizational
    Domains, all DMARC feedback will be directed to the PSO if that PSO
    itself has a DMARC Policy Record that specifies a "rua" tag.  Any non-DMARC
    Organizational Domain would have its Feedback Reports redirected to
    the PSO.  The content of such reports, particularly for existing
    domains, is privacy sensitive.

PSOs will receive feedback on non-existent domains, which may be
similar to existing Organizational Domains.  Feedback related to such
domains have a small risk of carrying information related to
an actual Organizational Domain.  To minimize this potential concern,
PSD DMARC feedback **MUST** be limited to Aggregate Reports.  Failure
Reports carry more detailed information and present a greater risk.

# Security Considerations

While reviewing this document and its Security Considerations, it is ideal
that the reader would also review Privacy Considerations above, as well as
the Privacy Considerations and Security Considerations in section
[@I-D.ietf-dmarc-dmarcbis, 9] and [@I-D.ietf-dmarc-dmarcbis, 10] of
[@I-D.ietf-dmarc-dmarcbis].

## Report Contents as an Attack

Aggregate reports are supposed to be processed automatically. An attacker 
might attempt to compromise the integrity or availability of the report 
processor by sending malformed reports. In particular, the archive 
decompressor and XML parser are at risk to resource exhaustion 
attacks (zip bomb or XML bomb).

## False Information

The data contained within aggregate reports may be forged. An attacker might
attempt to interfere with or influence policy decisions by submitting false 
reports in large volume. The attacker could also be attempting to influence
platform architecture decisions. A volume-based attack may also impact the
ability for a report receiver to accept reports from other entities.

## Disclosure of Filtering Information

While not specified in this document itself, the availability of extensions 
could enable the report generator to disclose information about message 
placement (Inbox/Spam/etc).  This is very much discouraged as it could
relay this information to a malicious party, allowing them to understand
more about filtering methodologies at a receiving entity.

{backmatter}

# DMARC XML Schema

<{{dmarc-xml-0.2.xsd}}

# Sample Report

<{{dmarc-xml-0.2.xml}}

Acknowledgements

Many thanks are deserved to those that helped create this document.  Much of
the content was created from the original [@!RFC7489], and has now been 
updated to be more clear and correct some outstanding issues. The IETF 
DMARC Working Group has spent much time working to finalize this effort,
and significant contributions were made by Seth Blank, Todd Herr, Steve Jones,
Murray S. Kucherawy, Barry Leiba, John Levine, Scott Kitterman, Daniel Kvål,
Martijn van der Lee, Alessandro Veseley, and Matthäus Wander.
