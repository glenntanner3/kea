// Copyright (C) 2013-2015 Internet Systems Consortium, Inc. ("ISC")
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

/// @file pkt_receive_co.cc Defines the pkt4_receive and pkt6_receive callout functions.

#include <config.h>
#include <hooks/hooks.h>
#include <dhcp/pkt4.h>
#include <dhcp/dhcp6.h>
#include <dhcp/pkt6.h>
#include <user_chk.h>
#include <user_chk_log.h>
#include <dhcp/option_vendor.h>

using namespace isc::log;
using namespace isc::dhcp;
using namespace isc::hooks;
using namespace user_chk;
using namespace std;

// Functions accessed by the hooks framework use C linkage to avoid the name
// mangling that accompanies use of the C++ compiler as well as to avoid
// issues related to namespaces.
extern "C" {

/// @brief  This callout is called at the "pkt4_receive" hook.
///
/// This function determines if the DHCP client identified by the inbound
/// DHCP query packet is in the user registry.
/// Upon entry, the registry is refreshed. Next the hardware address is
/// extracted from query and saved to the context as the "query_user_id".
/// This id is then used to search the user registry.  The resultant UserPtr
/// whether the user is found or not, is saved to the callout context as
/// "registered_user".   This makes the registered user, if not null, available
/// to subsequent callouts.
///
/// @param handle CalloutHandle which provides access to context.
///
/// @return 0 upon success, non-zero otherwise.
int pkt4_receive(CalloutHandle& handle) {
    if (!user_registry) {
        std::cout << "DHCP UserCheckHook : pkt4_receive UserRegistry is null"
                  << std::endl;
        return (1);
    }

    try {
        // Refresh the registry.
        user_registry->refresh();

        // Get the HWAddress to use as the user identifier.
        Pkt4Ptr query;
        handle.getArgument("query4", query);
        HWAddrPtr hwaddr = query->getHWAddr();

        // Store the id we search with so it is available down the road.
        handle.setContext(query_user_id_label, hwaddr);

        // Look for the user in the registry.
        UserPtr registered_user = user_registry->findUser(*hwaddr);

        // Store user regardless. Empty user pointer means non-found. It is
        // cheaper to fetch it and test it, than to use an exception throw.
        handle.setContext(registered_user_label, registered_user);
        std::cout << "DHCP UserCheckHook : pkt4_receive user : "
                  << hwaddr->toText() << " is "
                  << (registered_user ? " registered" : " not registered")
                  << std::endl;
    } catch (const std::exception& ex) {
        std::cout << "DHCP UserCheckHook : pkt4_receive unexpected error: "
                  << ex.what() << std::endl;
        return (1);
    }

    return (0);
}

/// @brief  This callout is called at the "pkt6_receive" hook.
///
/// This function determines if the DHCP client identified by the inbound
/// DHCP query packet is in the user registry.
/// Upon entry, the registry is refreshed. Next the DUID is extracted from
/// query and saved to the context as the "query_user_id". This id is then
/// used to search the user registry.  The resultant UserPtr whether the user
/// is found or not, is saved to the callout context as "registered_user".
/// This makes the registered user, if not null, available to subsequent
/// callouts.
///
/// @param handle CalloutHandle which provides access to context.
///
/// @return 0 upon success, non-zero otherwise.
int pkt6_receive(CalloutHandle& handle) {
    if (!user_registry) {
        std::cout << "DHCP UserCheckHook : pkt6_receive UserRegistry is null"
                  << std::endl;
        return (1);
    }

    try {
        // Refresh the registry.
        user_registry->refresh();

        // Fetch the inbound packet.
        Pkt6Ptr query;
        handle.getArgument("query6", query);
        
        OptionVendorPtr option_vendor;
        
        // Get all vendor option and look for the one with the ISC enterprise id.
        OptionCollection vendor_options = query->getOptions(D6O_VENDOR_OPTS);
        for (OptionCollection::const_iterator opt = vendor_options.begin(); opt != vendor_options.end(); ++opt) {
            option_vendor = boost::dynamic_pointer_cast<OptionVendor>(opt->second);
            if (option_vendor) {
                if (option_vendor->getVendorId() == "20974") { //our vendor ID
                    LOG_DEBUG(user_chk_logger, DBGLVL_TRACE_BASIC, "Matched enterprise vendor ID");
                    break;
                }
                option_vendor.reset();
            }
        }
        
        UserPtr registered_user = NULL;
        
        if (option_vendor) {
            OptionPtr option_foo = option_vendor->getOption(1);
            LOG_DEBUG(user_chk_logger, DBGLVL_TRACE_BASIC, "Value of 1 --> %1").arg(option_foo->toText());
            
            registered_user = user_registry->findUser(option_foo->getData());
        }
            
        // Store user regardless. Empty user pointer means non-found. It is
        // cheaper to fetch it and test it, than to use an exception throw.
        handle.setContext(registered_user_label, registered_user);
        LOG_DEBUG(user_chk_logger, DBGLVL_TRACE_BASIC, "%1 is %2").arg(option_foo->toText(), (registered_user ? " registered" : " not registered"));
    } catch (const std::exception& ex) {
        std::cout << "DHCP UserCheckHook : pkt6_receive unexpected error: "
                  << ex.what() << std::endl;
        return (1);
    }

    return (0);
}

} // end extern "C"
