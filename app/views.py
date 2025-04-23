"""
Contains views for handling domain analysis requests
"""

from django.shortcuts import render, redirect
from django_ratelimit.decorators import ratelimit
from .network.domain import Domain
from .forms import DomainForm

@ratelimit(key="ip", rate="3/m", method="POST", block=False)
def analysis(request):
    """
    Handles the domain analysis form submission and displays the results on the same page. 
    Includes rate limiting to prevent abuse (max 3 requests per minute per IP),
    """
    form = DomainForm(request.POST or None)
    result = None
    rate_limited = getattr(request, "limited", False)

    if request.method == "POST":
        if rate_limited:
            form.add_error(None, "Too many requests. Please wait a moment and try again.")
        elif form.is_valid():
            domain_name = form.cleaned_data["domain"]
            try:
                target = Domain(domain_name)
                result = {
                    "target": target.domain,
                    "headers": target.headers(),
                    "dns_records": target.dns_records(),
                    "domain_info": target.domain_info(),
                    "reversed_dns": target.reversed_dns(),
                    "ip_info": target.ip_info(),
                    "ssl_cert": target.ssl_cert()
                }
                request.session["domain_analysis_result"] = result
                return redirect("report")
            except Exception as error:
                form.add_error(None, f"Invalid domain name: {error}")

    return render(request, "analysis.html", {"form": form, "result": result})

def report(request):
    """
    Displays the domain analysis results on the report page.
    Retrieves results from session after the analysis.
    """
    result = request.session.get("domain_analysis_result", None)
    if result is None:
        message = "No analysis available. Scan a website on the Analysis page to get a report."
        return render(request, "report.html", {"empty": message})
    del request.session['domain_analysis_result']
    return render(request, "report.html", {"result": result})

def contact(request):
    """ Displays a static contact page """
    return render(request, "contact.html")
