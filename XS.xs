#define PERL_NO_GET_CONTEXT
#define NO_XSLOCKS
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

static Perl_keyword_plugin_t prev_plugin;

static int keyword_plugin(pTHX_ char *kw, STRLEN kwlen, OP **op_out) {
	HV *hints = GvHV(PL_hintgv);
	int is_enabled = hv_fetchs(GvHV(PL_hintgv), "Try::Tiny::XS/enabled", 0) != NULL;

	if (is_enabled && strnEQ("try", kw, kwlen)) {
		OP *body = parse_block(0);
		lex_read_space(0);

		OP *catch = NULL;

		if (strnEQ("catch", PL_parser->bufptr, 5)) {
			lex_read_to(PL_parser->bufptr + 5);
			lex_read_space(0);

			catch = parse_block(0);
			lex_read_space(0);
		}

		while (strnEQ("finally", PL_parser->bufptr, 7)) {
			lex_read_to(PL_parser->bufptr + 7);
			lex_read_space(0);
			OP * finally = parse_block(0);
			lex_read_space(0);
		}

		OP *block = NULL;
		if (catch != NULL) {
			op_append_elem(OP_LINESEQ, body, newSVOP(OP_CONST, 0, &PL_sv_yes));

			op_prepend_elem(
				OP_LINESEQ,
				newASSIGNOP(0,
					newUNOP(OP_RV2SV, 0, newGVOP(OP_GV, 0, PL_errgv)),
					OP_SASSIGN,
					newUNOP(OP_RV2SV, 0, newGVOP(OP_GV, OPf_MOD, PL_defgv))),
				catch);

			OP *eval = newUNOP(OP_ENTERTRY, 0, body);

			OP *cond = newLOGOP(OP_OR, 0, eval, catch);

			block = cond;
		} else {
			block = newUNOP(OP_ENTERTRY, 0, body);
		}

		OP *local_def = newASSIGNOP(0,
			newUNOP(OP_RV2SV, 0, newGVOP(OP_GV, 0, PL_defgv)),
			OP_SASSIGN,
			newUNOP(OP_RV2SV, OPf_REF | OPf_MOD, newGVOP(OP_GV, 0, PL_defgv)));

		cBINOPx(local_def)->op_last->op_private |= OPpLVAL_INTRO;

		OP *local_err = newASSIGNOP(0,
			newUNOP(OP_RV2SV, 0, newGVOP(OP_GV, 0, PL_errgv)),
			OP_SASSIGN,
			newUNOP(OP_RV2SV, OPf_REF | OPf_MOD, newGVOP(OP_GV, 0, PL_errgv)));

		cBINOPx(local_err)->op_last->op_private |= OPpLVAL_INTRO;

		OP *enter = newOP(OP_ENTER, 0);
		OP *leave = newLISTOP(OP_LEAVE, 0, NULL, NULL);
		op_append_elem(OP_LEAVE, leave, enter);
		op_append_elem(OP_LEAVE, leave, local_def);
		op_append_elem(OP_LEAVE, leave, local_err);
		op_append_elem(OP_LEAVE, leave, block);

		*op_out = leave;

		return KEYWORD_PLUGIN_EXPR;
	}

	if (prev_plugin) {
		return prev_plugin(aTHX_ kw, kwlen, op_out);
	} else {
		return KEYWORD_PLUGIN_DECLINE;
	}
}

MODULE = Try::Tiny::XS		PACKAGE = Try::Tiny::XS

BOOT:
	prev_plugin = PL_keyword_plugin;
	PL_keyword_plugin = keyword_plugin;
