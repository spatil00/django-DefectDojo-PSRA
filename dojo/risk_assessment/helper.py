import logging
from contextlib import suppress

from django.urls import reverse
from django.utils import timezone

import dojo.risk_acceptance.helper as ra_helper
from dojo.jira_link.helper import escape_for_jira
from dojo.models import Dojo_User, Finding, Notes, Risk_Assessment
from dojo.utils import get_full_url

logger = logging.getLogger(__name__)
# Create your tests here.

"""
def reinstate(risk_assessment, old_expiration_date):
    if risk_assessment.expiration_date_handled:
        logger.info("Reinstating risk acceptance %i:%s with %i findings", risk_acceptance.id, risk_acceptance, len(risk_acceptance.accepted_findings.all()))

        expiration_delta_days = get_system_setting("risk_acceptance_form_default_days", 90)
        risk_assessment.expiration_date = timezone.now() + relativedelta(days=expiration_delta_days)

        reinstated_findings = []
        for finding in risk_assessment.accepted_findings.all():
            if finding.active:
                logger.debug("%i:%s: accepting a.k.a. deactivating finding", finding.id, finding)
                finding.active = False
                finding.risk_accepted = True
                # Update any endpoint statuses on each of the findings
                update_endpoint_statuses(finding, accept_risk=True)
                finding.save(dedupe_option=False)
                reinstated_findings.append(finding)
            else:
                logger.debug("%i:%s: already inactive, not making any changes", finding.id, finding)

        # best effort JIRA integration, no status changes
        post_jira_comments(risk_acceptance, risk_acceptance.accepted_findings.all(), reinstation_message_creator)

    risk_acceptance.expiration_date_handled = None
    risk_acceptance.expiration_date_warned = None
    risk_acceptance.save()
"""


def delete(eng, risk_assessment):
    findings = risk_assessment.assessed_findings.all()
    for finding in findings:
        finding.active = True
        finding.risk_assessed = False
        # Update any endpoint statuses on each of the findings
        update_endpoint_statuses(finding, assess_risk=False)
        finding.save(dedupe_option=False)

    risk_assessment.assessed_findings.clear()
    risk_assessment.delete()


def remove_finding_from_risk_assessment(user: Dojo_User, risk_assessment: Risk_Assessment, finding: Finding) -> None:
    logger.debug("removing finding %i from risk acceptance %i", finding.id, risk_assessment.id)
    risk_assessment.assessed_findings.remove(finding)
    finding.active = True
    finding.risk_assessed = False
    # Update any endpoint statuses on each of the findings
    update_endpoint_statuses(finding, assess_risk=False)
    finding.save(dedupe_option=False)
    # best effort jira integration, no status changes
    # post_jira_comments(risk_acceptance, [finding], unaccepted_message_creator)
    # Add a note to reflect that the finding was removed from the risk acceptance
    if user is not None:
        finding.notes.add(Notes.objects.create(
            entry=(
                f"{Dojo_User.generate_full_name(user)} ({user.id}) removed this finding from the risk acceptance: "
                f'"{risk_assessment.name}" ({get_view_risk_assessment(risk_assessment)})'
            ),
            author=user,
        ))

    return


def add_findings_to_risk_assessment(user: Dojo_User, risk_assessment: Risk_Assessment, findings: list[Finding]) -> None:
    for finding in findings:
        if not finding.duplicate or finding.risk_assessed:
            finding.active = False
            finding.risk_assessed = True
            finding.risk = risk_assessment

            # Update mitigation to finding if needed
            if finding.mitigation != risk_assessment.finding_mitigation:
                finding.mitigation = risk_assessment.finding_mitigation

            # Manage Risk acceptance , Simple risk acceptance is done but
            # Decision decritpion is not updated in Risk Acceptance but updated in Risk Assessment
            # As in Risk assessment action and rational needs to be written if risk accepted or not
            if risk_assessment.accept_risk:
                if finding.test.engagement.product.enable_simple_risk_acceptance:
                    ra_helper.simple_risk_accept(user, finding, perform_save=False)
            elif finding.risk_accepted:
                ra_helper.risk_unaccept(user, finding, perform_save=False)

            finding.save(dedupe_option=False)
            # Update any endpoint statuses on each of the findings
            update_endpoint_statuses(finding, assess_risk=True)
            # risk_assessment.assessed_findings.add(finding)

        # Add a note to reflect that the finding was removed from the risk acceptance
        if user is not None:
            finding.notes.add(Notes.objects.create(
                entry=(
                    f"{Dojo_User.generate_full_name(user)} ({user.id}) added this finding to the risk assessment: "
                    f'"{risk_assessment.name}" ({get_view_risk_assessment(risk_assessment)})'
                ),
                author=user,
            ))
    risk_assessment.save()
    # best effort jira integration, no status changes
    #  post_jira_comments(risk_assessment, findings, assessed_message_creator)

    return


def assessed_message_creator(risk_assessment, heads_up_days=0):
    if risk_assessment:
        return "Finding has been added to risk assessment [({})|{}] with {} findings (expires on {})".format(
            escape_for_jira(risk_assessment.name),
            get_full_url(reverse("view_risk_assessment", args=(risk_assessment.engagement.id, risk_assessment.id))),
            len(risk_assessment.assessed_findings.all()), timezone.localtime(risk_assessment.expiration_date).strftime("%b %d, %Y"))
    return "Finding has been risk assessed"


"""def post_jira_comments(risk_assessment, findings, message_factory, heads_up_days=0):
    if not risk_assessment:
        return

    jira_project = jira_helper.get_jira_project(risk_assessment.engagement)

    if jira_project and jira_project.risk_acceptance_expiration_notification:
        jira_instance = jira_helper.get_jira_instance(risk_assessment.engagement)

        if jira_instance:
            jira_comment = message_factory(risk_assessment, heads_up_days)

            for finding in findings:
                if finding.has_jira_issue:
                    logger.debug("Creating JIRA comment for something risk assessment related")
                    jira_helper.add_simple_jira_comment(jira_instance, finding.jira_issue, jira_comment)"""


def get_view_risk_assessment(risk_assessment: Risk_Assessment) -> str:
    """Return the full qualified URL of the view risk assessment page."""
    # Suppressing this error because it does not happen under most circumstances that a risk acceptance does not have engagement
    with suppress(AttributeError):
        get_full_url(
            reverse("view_risk_assessment", args=(risk_assessment.engagement.id, risk_assessment.id)),
        )
    return ""


def update_endpoint_statuses(finding: Finding, *, assess_risk: bool) -> None:
    for status in finding.status_finding.all():
        if assess_risk:
            status.active = False
            status.mitigated = True
            status.risk_accepted = True
        else:
            status.active = True
            status.mitigated = False
            status.risk_accepted = False
        status.last_modified = timezone.now()
        status.save()
