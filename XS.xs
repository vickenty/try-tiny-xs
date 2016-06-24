#define PERL_NO_GET_CONTEXT
#define NO_XSLOCKS
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

struct finally {
	SV* code;
	SV* error;
};

void call_finally(pTHX_ struct finally *finally)
{
	dSP;
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	if (finally->error != NULL) {
		mXPUSHs(finally->error);
	}
	PUTBACK;
	call_sv(finally->code, G_VOID | G_EVAL);
	SPAGAIN;
	if (SvTRUE(ERRSV)) {
		warn(
		  "Execution of finally() block CODE(0x%p) resulted in an exception.\n"
		  "Original exception text follows:\n\n%s", 
		     	(void*) finally->code, 
			SvPV_nolen(ERRSV));
	}
	FREETMPS;
	LEAVE;
	PUTBACK;
	Safefree(finally);
}

MODULE = Try::Tiny::XS		PACKAGE = Try::Tiny::XS

PROTOTYPES: ENABLE

void
try(SV* body, ...)
	PROTOTYPE: &;@
	PREINIT:
	U32 context;
	I32 retval;
	int index;
	int error = 0;
	SV* catch = NULL;
	SV* prev_error;
	int nfinally = 0;
	struct finally** finally;
	dXCPT;

	PPCODE:
	context = GIMME_V;

	ENTER;

	finally = (struct finally**) alloca(sizeof(struct finally*) * items);
	for (index = 1; index < items; index++) {
		SV* item = ST(index);

		if (sv_isa(item, "Try::Tiny::Catch")) {
			catch = SvRV(item);
			continue;
		}
		if (sv_isa(item, "Try::Tiny::Finally")) {
			Newx(finally[nfinally], 1, struct finally);
			finally[nfinally]->code = SvRV(item);
			finally[nfinally]->error = NULL;
			SAVEDESTRUCTOR_X(call_finally, finally[nfinally]);
			nfinally++;
		}
	}


	prev_error = newSVsv(ERRSV);
	save_item(ERRSV);

	PUSHMARK(SP);
	PUTBACK;
	retval = call_sv(body, G_EVAL | context);
	SPAGAIN;

	if (SvTRUE(ERRSV)) {
		error = 1;
		for (index = 0; index < nfinally; index++) {
			finally[index]->error = newSVsv(ERRSV);
		}
	}

	if (error && catch != NULL) {
		SAVE_DEFSV;
		DEFSV_set(newSVsv(ERRSV));
		sv_setsv(ERRSV, prev_error);
		PUSHMARK(SP);
		XPUSHs(UNDERBAR);
		PUTBACK;
		retval = call_sv(catch, context);
		SPAGAIN;
	}

	LEAVE;
	PUTBACK;
