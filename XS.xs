#define PERL_NO_GET_CONTEXT
#define NO_XSLOCKS
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

static Perl_keyword_plugin_t prev_plugin;

/* SUCCESS
 *
 * Mark target as true if child returned via normal control flow. If child op
 * does a non-local exit (via die or goto), do nothing.
 *
 * Target points to the success flag.
 */

static XOP xop_success;

static OP * xop_success_impl(pTHX) {
	dTARGET;
	sv_setsv(TARG, &PL_sv_yes);
	return NORMAL;
}

static OP *S_newSUCCESS(pTHX_ PADOFFSET target, OP *first) {
	OP *op = newUNOP(OP_NULL, OPf_WANT_VOID, first);
	op->op_type = OP_CUSTOM;
	op->op_ppaddr = xop_success_impl;
	op->op_targ = target;
	return op;
}

#define newSUCCESS(a,b) S_newSUCCESS(aTHX_ a,b)

/* BRANCH
 *
 * Call the branch if target is false. Used to invoke catch block.
 *
 * Target points to the success flag.
 */

static XOP xop_branch;

static OP * xop_branch_impl(pTHX) {
	dTARGET;
	if (!SvTRUE(TARG)) {
		return cLOGOP->op_other;
	}
	return NORMAL;
}

static OP *S_newBRANCH(pTHX_ PADOFFSET target, OP *first, OP *other) {
	OP *op = newLOGOP(OP_CUSTOM, 0, first, other);
	cUNOPx(op)->op_first->op_ppaddr = xop_branch_impl;
	cUNOPx(op)->op_first->op_targ = target;
	return op;
}

#define newBRANCH(a,b,c) S_newBRANCH(aTHX_ a,b,c)

/* PREPARE
 *
 * Prepare to enter try block. Localize $_ and $@, and copy $@ into target: we
 * will need it to restore $@ before entering catch block.
 *
 * Target points to a location to save $@ to.
 */

static XOP xop_prepare;

static OP *xop_prepare_impl(pTHX) {
	dTARGET;
	sv_setsv(TARG, ERRSV);
	save_scalar(PL_errgv);
	SAVE_DEFSV;
	return NORMAL;
}

static OP *S_newPREPARE(pTHX_ PADOFFSET preverr) {
	OP *op = newOP(OP_NULL, 0);
	op->op_type = OP_CUSTOM;
	op->op_ppaddr = xop_prepare_impl;
	op->op_targ = preverr;
	return op;
}

#define newPREPARE(a) S_newPREPARE(aTHX_ a)

/* RESET
 *
 * Reset the success flag to false.
 *
 * Target points to the success flag.
 */

static XOP xop_reset;

static OP *xop_reset_impl(pTHX) {
	dTARGET;
	sv_setsv(TARG, NULL);
	return NORMAL;
}

static OP *S_newRESET(pTHX_ PADOFFSET targ) {
	OP *op = newOP(OP_NULL, 0);
	op->op_type = OP_CUSTOM;
	op->op_ppaddr = xop_reset_impl;
	op->op_targ = targ;
	return op;
}

#define newRESET(a) S_newRESET(aTHX_ a)


/* CATCH
 *
 * Prepare to execute catch block. Push $@ value to the stack and restore $@ to
 * the value before try.
 *
 * Target points to previously saved $@ value.
 */

static XOP xop_catch;

static OP *xop_catch_impl(pTHX) {
	dSP;
	dTARGET;
	mXPUSHs(newSVsv(ERRSV));
	sv_setsv(ERRSV, TARG);
	PUTBACK;
	return NORMAL;
}

static OP *S_newCATCH(pTHX_ PADOFFSET preverr) {
	OP *op = newOP(OP_NULL, 0);
	op->op_type = OP_CUSTOM;
	op->op_ppaddr = xop_catch_impl;
	op->op_targ = preverr;
	return op;
}

#define newCATCH(a) S_newCATCH(aTHX_ a)

/* RESTORE
 *
 * Restore $@ after entering try to the value before eval.
 *
 * Target points to previously saved $@ value.
 */

static XOP xop_restore;

static OP *xop_restore_impl(pTHX) {
	dTARGET;
	sv_setsv(ERRSV, TARG);
	return NORMAL;
}

static OP *S_newRESTORE(pTHX_ PADOFFSET targ) {
	OP *op = newOP(OP_NULL, 0);
	op->op_type = OP_CUSTOM;
	op->op_ppaddr = xop_restore_impl;
	op->op_targ = targ;
	return op;
}

#define newRESTORE(a) S_newRESTORE(aTHX_ a)

/* FINALLY
 *
 * Arrange to call finally blocks when we leave scope.
 * Target points to an arrayref: we reserve first element to indicate
 * exception, if any, followed by coderefs of the finally blocks themselves.
 *
 * Expects an arrayref of coderefs (finally blocks) at the top of the stack.
 *
 * Target points to a location that can be shared with FINALLY_SETERR.
 */

static void invoke_finally(pTHX_ void *arg) {
	dSP;
	SV *finlist_ref = (SV*) arg;
	AV *finlist = (AV*) SvRV(finlist_ref);
	SSize_t ix, top = av_top_index(finlist);
	SV **err = av_fetch(finlist, 0, 0);

	for (ix = top; ix > 0; ix--) {
		SV **fin = av_fetch(finlist, ix, 0);
		PUSHMARK(SP);
		if (err) {
			XPUSHs(*err);
			PUTBACK;
		}
		call_sv(*fin, G_VOID | G_EVAL | G_DISCARD);
		SPAGAIN;
		if (SvTRUE(ERRSV)) {
		       warn(
			 "Execution of finally() block CODE(0x%p) resulted in an exception.\n"
			 "Original exception text follows:\n\n%s",
			       (void*) SvRV(*fin), SvPV_nolen(ERRSV));
		}
	}
}

static XOP xop_finally;

static OP *xop_finally_impl(pTHX) {
	dSP;
	dTARGET;
	SV *finlist = POPs;
	PUTBACK;
	av_unshift((AV*) SvRV(finlist), 1);
	sv_setsv(TARG, finlist);
	SAVEDESTRUCTOR_X(invoke_finally, finlist);
	return NORMAL;
}

static OP *S_newFINALLY(pTHX_ PADOFFSET targ, OP *list) {
	OP *op = newUNOP(OP_CUSTOM, 0, list);
	op->op_ppaddr = xop_finally_impl;
	op->op_targ = targ;
	return op;
}

#define newFINALLY(a,b) S_newFINALLY(aTHX_ a,b)

/* FINALLY_SETERR
 *
 * Assign the error to the element 0 of finally list, which is reserved for
 * this purpose by FINALLY.
 *
 * Target points to a location that was written to by FINALLY.
 */

static XOP xop_finally_seterr;

static OP *xop_finally_seterr_impl(pTHX) {
	dTARGET;
	av_store((AV*) SvRV(TARG), 0, newSVsv(ERRSV));
	return NORMAL;
}

static OP *S_newFINALLY_SETERR(pTHX_ PADOFFSET targ) {
	OP *op = newOP(OP_CUSTOM, 0);
	op->op_ppaddr = xop_finally_seterr_impl;
	op->op_targ = targ;
	return op;
}

#define newFINALLY_SETERR(a) S_newFINALLY_SETERR(aTHX_ a)

/* SCOPE
 *
 * Scope contains the location of the success bit for the try block we are
 * parsing now. Try blocks can be nested, so this is a stack of scopes
 * actually, and `scope` always points to the currently parsed try block
 * (innermost).
 *
 * This is used to patch RETURN ops to set the success bit as well as normal
 * exit.
 */

static struct scope {
	PADOFFSET target;
	struct scope *prev;
} *scope;

/* KEYWORD PLUGIN
 *
 * Intercept `try` keyword and assemble an op-tree that behaves like a
 * Try::Tiny would. Try block is inlined in the caller subroutine to avoid
 * subroutine call overhead.
 *
 * To preserve the scalar/list context, instead of returning success value from
 * eval directly, we use custom SUCCESS op wrapped around all return values
 * (one around try block itself for implict return, and around arguments of all
 * `return` operators within the block).
 *
 * For the same reason, catch block is called via a custom BRANCH op as well.
 *
 * Finally blocks are arranged to be called via a custom destructor.
 */

static int keyword_plugin(pTHX_ char *kw, STRLEN kwlen, OP **op_out) {
	HV *hints = GvHV(PL_hintgv);
	int is_enabled = hv_fetchs(GvHV(PL_hintgv), "Try::Tiny::XS/enabled", 0) != NULL;

	if (is_enabled && strnEQ("try", kw, kwlen)) {
		PADOFFSET success = pad_alloc(OP_ENTERTRY, SVs_PADTMP);
		PADOFFSET preverr = pad_alloc(OP_LEAVETRY, SVs_PADTMP);
		PADOFFSET finaref = pad_alloc(OP_ANONLIST, SVs_PADTMP);

		struct scope *top;

		Newx(top, 1, struct scope);
		top->target = success;
		top->prev = scope;
		scope = top;

		OP *body = parse_block(0);
		lex_read_space(0);

		scope = top->prev;
		Safefree(top);

		body = op_prepend_elem(OP_LINESEQ, newRESTORE(preverr), body);

		OP *block = newLISTOP(OP_LEAVE, 0, newOP(OP_ENTER, 0), NULL);
		op_append_elem(block->op_type, block, newPREPARE(preverr));
		op_append_elem(block->op_type, block, newRESET(success));

		OP *finlist = NULL;
		while (strnEQ("finally", PL_parser->bufptr, 7)) {
			lex_read_to(PL_parser->bufptr + 7);
			lex_read_space(0);

			if (!finlist)
				finlist = newLISTOP(OP_ANONLIST, 0, newOP(OP_PUSHMARK, 0), NULL);

			I32 floor = start_subparse(0, CVf_ANON);
			OP *finop = newANONSUB(floor, NULL, parse_block(0));
			finlist = op_append_elem(OP_ANONLIST, finlist, finop);
			lex_read_space(0);
		}

		OP *catch_cv = NULL;
		if (strnEQ("catch", PL_parser->bufptr, 5)) {
			lex_read_to(PL_parser->bufptr + 5);
			lex_read_space(0);

			I32 floor = start_subparse(0, CVf_ANON);
			catch_cv = newANONSUB(floor, NULL, parse_block(0));
			lex_read_space(0);
		}

		while (strnEQ("finally", PL_parser->bufptr, 7)) {
			lex_read_to(PL_parser->bufptr + 7);
			lex_read_space(0);

			if (!finlist)
				finlist = newLISTOP(OP_ANONLIST, 0, newOP(OP_PUSHMARK, 0), NULL);

			I32 floor = start_subparse(0, CVf_ANON);
			OP *finop = newANONSUB(floor, NULL, parse_block(0));
			finlist = op_append_elem(OP_ANONLIST, finlist, finop);
			lex_read_space(0);
		}

		if (finlist) {
			op_append_elem(block->op_type, block, newFINALLY(finaref, newUNOP(OP_SREFGEN, 0, finlist)));
		}

		OP *catch;
		if (catch_cv) {
			GV *invoke = gv_fetchpv("Try::Tiny::XS::invoke_catch", 0, SVt_PVCV);
			assert(invoke != NULL);

			OP *args = newLISTOP(OP_LIST, 0, catch_cv, NULL);
			if (finlist) {
				args = op_append_elem(OP_LIST, args, newFINALLY_SETERR(finaref));
			}
			args = op_append_elem(OP_LIST, args, newCATCH(preverr));
			args = op_append_elem(OP_LIST, args, newUNOP(OP_RV2CV, 0, newGVOP(OP_GV, 0, invoke)));

			catch = newUNOP(OP_ENTERSUB, OPf_STACKED, args);
		}
		else {
			if (finlist) {
				catch = newFINALLY_SETERR(finaref);
			} else {
				catch = newOP(OP_UNDEF, 0);
			}
		}


		OP *eval = newUNOP(OP_ENTERTRY, 0, newSUCCESS(success, body));
		OP *catch_maybe = newBRANCH(success, eval, catch);

		/* newLOGOP will force scalar context on its children, while we
		 * want to inherit the context of the outermost block.
		 */
		eval->op_flags &= ~OPf_WANT;
		cUNOPx(eval)->op_first->op_flags &= ~OPf_WANT;

		op_append_elem(block->op_type, block, catch_maybe);

		*op_out = block;

		return KEYWORD_PLUGIN_EXPR;
	}

	if (is_enabled && strnEQ("return", kw, kwlen) && scope) {
		OP *list = parse_listexpr(0);
		OP *succ = newSUCCESS(scope->target, list);
		*op_out = newLISTOP(OP_RETURN, 0, succ, NULL);
		return KEYWORD_PLUGIN_STMT;
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

	XopENTRY_set(&xop_success, xop_name, "xop_success");
	XopENTRY_set(&xop_success, xop_desc, "assign true to target");
	XopENTRY_set(&xop_success, xop_class, OA_UNOP);
	Perl_custom_op_register(aTHX_ xop_success_impl, &xop_success);

	XopENTRY_set(&xop_branch, xop_name, "xop_branch");
	XopENTRY_set(&xop_branch, xop_desc, "like or, but checks target instead of stack top");
	XopENTRY_set(&xop_branch, xop_class, OA_LOGOP);
	Perl_custom_op_register(aTHX_ xop_branch_impl, &xop_branch);

	XopENTRY_set(&xop_prepare, xop_name, "xop_prepare");
	XopENTRY_set(&xop_prepare, xop_desc, "localize $@ and $_");
	XopENTRY_set(&xop_prepare, xop_class, OA_BASEOP);
	Perl_custom_op_register(aTHX_ xop_prepare_impl, &xop_prepare);

	XopENTRY_set(&xop_catch, xop_name, "xop_catch");
	XopENTRY_set(&xop_catch, xop_desc, "restore $@ before catch block");
	XopENTRY_set(&xop_catch, xop_class, OA_BASEOP);
	Perl_custom_op_register(aTHX_ xop_catch_impl, &xop_catch);

	XopENTRY_set(&xop_reset, xop_name, "xop_reset");
	XopENTRY_set(&xop_reset, xop_desc, "like undef but with a target");
	XopENTRY_set(&xop_reset, xop_class, OA_BASEOP);
	Perl_custom_op_register(aTHX_ xop_reset_impl, &xop_reset);

	XopENTRY_set(&xop_restore, xop_name, "xop_restore");
	XopENTRY_set(&xop_restore, xop_desc, "restore $@ before try body");
	XopENTRY_set(&xop_restore, xop_class, OA_BASEOP);
	Perl_custom_op_register(aTHX_ xop_restore_impl, &xop_restore);

	XopENTRY_set(&xop_finally, xop_name, "xop_finally");
	XopENTRY_set(&xop_finally, xop_desc, "set up call to a finally block");
	XopENTRY_set(&xop_finally, xop_class, OA_UNOP);
	Perl_custom_op_register(aTHX_ xop_finally_impl, &xop_finally);

	XopENTRY_set(&xop_finally_seterr, xop_name, "xop_finally_seterr");
	XopENTRY_set(&xop_finally_seterr, xop_desc, "save error for finally blocks");
	XopENTRY_set(&xop_finally_seterr, xop_class, OA_UNOP);
	Perl_custom_op_register(aTHX_ xop_finally_seterr_impl, &xop_finally_seterr);
