%%%

	Title = "DMARC Aggregate Reporting"
	abbrev = "DMARC Aggregate Reporting"
	docName = "draft-ietf-dmarc-aggregate-reporting-00"
	category = "std"
	obsoletes = [7489]
	ipr = "trust200902"
	area = "Application"
	workgroup = "DMARC"
	submissiontype = "IETF"
	keyword = [""]
	
	date = "2020-11-11T00:00:00Z"
	
	[seriesInfo]
	name = "Internet-Draft"
	value = "draft-ietf-dmarc-aggregate-reporting-00"
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

DMARC allows for domain holders to request aggregate reports from receivers.
This report is an XML document, and contains extensible elements that allow for 
other types of data to be specified later.  The aggregate reports can be
submitted to the domain holder's specified destination as supported by the
receiver.

This document (along with others) obsoletes RFC7489.

{mainmatter}

# Introduction

A key component of DMARC is the ability for domain holders to request that
receivers provide various types of reports.  These reports allow domain holders
to have insight into which IP addresses are sending on their behalf, and some
insight into whether or not the volume may be legitimate.  These reports expose
information relating to the DMARC policy, as well as the outcome of 
SPF [@!RFC7208] & DKIM [@!RFC6376] validation.


## Terminology

The keywords **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**,
**SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL**, when they appear in this document, are
 to be interpreted as described in [@RFC2119].

# DMARC Feedback

Providing Domain Owners with visibility into how Mail Receivers implement
and enforce the DMARC mechanism in the form of feedback is critical to
establishing and maintaining accurate authentication deployments.  When
Domain Owners can see what effect their policies and practices are having,
they are better willing and able to use quarantine and reject policies.

## Verifying External Destinations

[https://trac.ietf.org/trac/dmarc/ticket/76]

## Aggregate Reports

The DMARC aggregate feedback report is designed to provide Domain
Owners with precise insight into:

*  authentication results,
*  corrective action that needs to be taken by Domain Owners, and
*  the effect of Domain Owner DMARC policy on email streams processed
   by Mail Receivers.

Aggregate DMARC feedback provides visibility into real-world email
streams that Domain Owners need to make informed decisions regarding
the publication of DMARC policy.  When Domain Owners know what
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

The format for these reports is defined in Appendix C.

The report SHOULD include the following data:

*  The DMARC policy discovered and applied, if any
*  The selected message disposition
*  The identifier evaluated by SPF and the SPF result, if any
*  The identifier evaluated by DKIM and the DKIM result, if any
*  For both DKIM and SPF, an indication of whether the identifier was
   in alignment
*  Data for each Domain Owner's subdomain separately from mail from
   the sender's Organizational Domain, even if there is no explicit
   subdomain policy
*  Sending and receiving domains
*  The policy requested by the Domain Owner and the policy actually
   applied (if different)
*  The number of successful authentications
*  The counts of messages based on all messages received, even if
   their delivery is ultimately blocked by other filtering agents

Note that Domain Owners or their agents may change the published
DMARC policy for a domain or subdomain at any time.  From a Mail
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
*  generate a report whose end time occurs when the updated policy
   was detected, regardless of any requested report interval.

The report SHOULD include the following data:

*  The DMARC policy discovered and applied, if any
*  The selected message disposition
*  The identifier evaluated by SPF and the SPF result, if any
*  The identifier evaluated by DKIM and the DKIM result, if any
*  For both DKIM and SPF, an indication of whether the identifier was
   in alignment
*  Data for each Domain Owner's subdomain separately from mail from
   the sender's Organizational Domain, even if there is no explicit
   subdomain policy
*  Sending and receiving domains
*  The policy requested by the Domain Owner and the policy actually
   applied (if different)
*  The number of successful authentications
*  The counts of messages based on all messages received, even if
   their delivery is ultimately blocked by other filtering agents

Note that Domain Owners or their agents may change the published
DMARC policy for a domain or subdomain at any time.  From a Mail
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
*  generate a report whose end time occurs when the updated policy
   was detected, regardless of any requested report interval.

### Transport

   Where the URI specified in a "rua" tag does not specify otherwise, a
   Mail Receiver generating a feedback report SHOULD employ a secure
   transport mechanism.

   The Mail Receiver, after preparing a report, MUST evaluate the
   provided reporting URIs in the order given.  Any reporting URI that
   includes a size limitation exceeded by the generated report (after
   compression and after any encoding required by the particular
   transport mechanism) MUST NOT be used.  An attempt MUST be made to
   deliver an aggregate report to every remaining URI, up to the
   Receiver's limits on supported URIs.

   If transport is not possible because the services advertised by the
   published URIs are not able to accept reports (e.g., the URI refers
   to a service that is unreachable, or all provided URIs specify size
   limits exceeded by the generated record), the Mail Receiver SHOULD
   send a short report (see Section 7.2.2) indicating that a report is
   available but could not be sent.  The Mail Receiver MAY cache that
   data and try again later, or MAY discard data that could not be sent.


#### Email

   The message generated by the Mail Receiver MUST be a [MAIL] message
   formatted per [MIME].  The aggregate report itself MUST be included
   in one of the parts of the message.  A human-readable portion MAY be
   included as a MIME part (such as a text/plain part).

   The aggregate data MUST be an XML file that SHOULD be subjected to
   GZIP compression.  Declining to apply compression can cause the
   report to be too large for a receiver to process (a commonly observed
   receiver limit is ten megabytes); doing the compression increases the
   chances of acceptance of the report at some compute cost.  The
   aggregate data SHOULD be present using the media type "application/
   gzip" if compressed (see [GZIP]), and "text/xml" otherwise.  The
   filename is typically constructed using the following ABNF:

     filename = receiver "!" policy-domain "!" begin-timestamp
                "!" end-timestamp [ "!" unique-id ] "." extension

     unique-id = 1*(ALPHA / DIGIT)

     receiver = domain
                ; imported from [MAIL]

     policy-domain   = domain

     begin-timestamp = 1*DIGIT
                       ; seconds since 00:00:00 UTC January 1, 1970
                       ; indicating start of the time range contained
                       ; in the report

     end-timestamp = 1*DIGIT
                     ; seconds since 00:00:00 UTC January 1, 1970
                     ; indicating end of the time range contained
                     ; in the report

     extension = "xml" / "xml.gz"

   The extension MUST be "xml" for a plain XML file, or "xml.gz" for an
   XML file compressed using GZIP.

   "unique-id" allows an optional unique ID generated by the Mail
   Receiver to distinguish among multiple reports generated
   simultaneously by different sources within the same Domain Owner.



   For example, this is a possible filename for the gzip file of a
   report to the Domain Owner "example.com" from the Mail Receiver
   "mail.receiver.example":

     mail.receiver.example!example.com!1013662812!1013749130.gz

   No specific MIME message structure is required.  It is presumed that
   the aggregate reporting address will be equipped to extract MIME
   parts with the prescribed media type and filename and ignore the
   rest.

   Email streams carrying DMARC feedback data MUST conform to the DMARC
   mechanism, thereby resulting in an aligned "pass" (see Section 3.1).
   This practice minimizes the risk of report consumers processing
   fraudulent reports.

   The RFC5322.Subject field for individual report submissions SHOULD
   conform to the following ABNF:

     dmarc-subject = %x52.65.70.6f.72.74 1*FWS       ; "Report"
                     %x44.6f.6d.61.69.6e.3a 1*FWS    ; "Domain:"
                     domain-name 1*FWS               ; from RFC 6376
                     %x53.75.62.6d.69.74.74.65.72.3a ; "Submitter:"
                     1*FWS domain-name 1*FWS
                     %x52.65.70.6f.72.74.2d.49.44.3a ; "Report-ID:"
                     msg-id                          ; from RFC 5322

   The first domain-name indicates the DNS domain name about which the
   report was generated.  The second domain-name indicates the DNS
   domain name representing the Mail Receiver generating the report.
   The purpose of the Report-ID: portion of the field is to enable the
   Domain Owner to identify and ignore duplicate reports that might be
   sent by a Mail Receiver.

   For instance, this is a possible Subject field for a report to the
   Domain Owner "example.com" from the Mail Receiver
   "mail.receiver.example".  It is line-wrapped as allowed by [MAIL]:

     Subject: Report Domain: example.com
         Submitter: mail.receiver.example
         Report-ID: <2002.02.15.1>

   This transport mechanism potentially encounters a problem when
   feedback data size exceeds maximum allowable attachment sizes for
   either the generator or the consumer.  See Section 7.2.2 for further
   discussion.


#### Other Methods

The specification as written allows for the addition of other
registered URI schemes to be supported in later versions.

# IANA Considerations

TBD

# Security Considerations

TBD

# Appendix A. DMARC XML Schema

<{{dmarc-xml-0.1.xsd}}

{backmatter}
