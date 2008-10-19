/*
 *  Phishing module: domain list implementation.
 *
 *  Copyright (C) 2007-2008 Sourcefire, Inc.
 *
 *  Authors: Török Edvin
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif


#ifndef CL_DEBUG
#define NDEBUG
#endif

#ifdef CL_THREAD_SAFE
#ifndef _REENTRANT
#define _REENTRANT
#endif
#endif

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "clamav.h"
#include "others.h"
#include "phishcheck.h"
#include "phish_domaincheck_db.h"
#include "regex_list.h"

int domainlist_match(const struct cl_engine* engine,char* real_url,const char* display_url,const struct pre_fixup_info* pre_fixup,int hostOnly,unsigned short* flags)
{
	const char* info;
	int rc = engine->domainlist_matcher ? regex_list_match(engine->domainlist_matcher,real_url,display_url,hostOnly ? pre_fixup : NULL,hostOnly,&info,0) : 0;
	return rc;
}

int init_domainlist(struct cl_engine* engine)
{
	if(engine) {
		engine->domainlist_matcher = (struct regex_matcher *) cli_malloc(sizeof(struct regex_matcher));
		if(!engine->domainlist_matcher)
			return CL_EMEM;
		((struct regex_matcher*)engine->domainlist_matcher)->mempool = engine->mempool;
		return init_regex_list(engine->domainlist_matcher);
	}
	else
		return CL_ENULLARG;
}

int is_domainlist_ok(const struct cl_engine* engine)
{
	return (engine && engine->domainlist_matcher) ? is_regex_ok(engine->domainlist_matcher) : 1;
}

void domainlist_done(struct cl_engine* engine)
{
	if(engine && engine->domainlist_matcher) {
		regex_list_done(engine->domainlist_matcher);
		free(engine->domainlist_matcher);
	}
}

