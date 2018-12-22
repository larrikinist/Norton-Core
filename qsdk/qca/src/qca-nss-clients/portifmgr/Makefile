##########################################################################
# Copyright (c) 2015, The Linux Foundation. All rights reserved.
# Permission to use, copy, modify, and/or distribute this software for
# any purpose with or without fee is hereby granted, provided that the
# above copyright notice and this permission notice appear in all copies.
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
# OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
##########################################################################

ccflags-y := -I$(obj)/../exports -I$(obj)/..  -I$(obj)/nss_hal/include
ccflags-y += -DNSS_CLIENT_BUILD_ID="$(BUILD_ID)"

#
# If you want to build qca-nss-portifmgr with QCA Ref design AP148 support
# set NSS_PORTIFMGR_REF_AP148
#     ccflags-y += -DNSS_PORTIFMGR_REF_AP148
# Otherwise qca-nss-portifmgr will only provide APIs for creating interfaces

obj-m += qca-nss-portifmgr.o
qca-nss-portifmgr-objs := nss_portifmgr.o

ccflags-y += -DNSS_PORTIFMGR_DEBUG_LEVEL=2 #-DNSS_PORTIFMGR_REF_AP148
