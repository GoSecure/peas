########################################################################
#  Copyright (C) 2013 Sol Birnbaum
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU General Public License
#  as published by the Free Software Foundation; either version 2
#  of the License, or (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA  02110-1301, USA.
########################################################################

from ..utils.wapxml import wapxmltree, wapxmlnode

class SmartForward:
    """http://msdn.microsoft.com/en-us/library/ee201840(v=exchg.80).aspx"""

    @staticmethod
    def build(client_id, source, mime, replace_mime=False, save_in_sent_items=True, template_id=None):
        smartforward_xmldoc_req = wapxmltree()
        xmlrootnode = wapxmlnode("SmartForward")
        smartforward_xmldoc_req.set_root(xmlrootnode, "composemail")
        xml_clientid_node = wapxmlnode("ClientId", xmlrootnode, client_id)
        xml_source_node = wapxmlnode("Source", xmlrootnode)
        if "FolderId" in source:
            wapxmlnode("FolderId", xml_source_node, source["FolderId"])
        if "ItemId" in source:
            wapxmlnode("ItemId", xml_source_node, source["ItemId"])
        if "LongId" in source:
            wapxmlnode("LongId", xml_source_node, source["LongId"])
        if "InstanceId" in source:
            wapxmlnode("InstanceId", xml_source_node, source["InstanceId"])
        xml_accountid_node = wapxmlnode("AccountId", xmlrootnode, display_name)
        xml_saveinsentiems_node = wapxmlnode("SaveInSentItems", xmlrootnode, str(int(save_in_sent_items)))
        if replace_mime:
            xml_replacemime_node = wapxmlnode("ReplaceMime", xmlrootnode)
        xml_mime_node = wapxmlnode("Mime", xmlrootnode, mime)
        xml_templateid_node = wapxmlnode("rm:TemplateID", xmlrootnode, template_id)
        return smartforward_xmldoc_req

    @staticmethod
    def parse(wapxml):

        namespace = "composemail"
        root_tag = "SmartForward"

        root_element = wapxml.get_root()
        if root_element.get_xmlns() != namespace:
            raise AttributeError("Xmlns '%s' submitted to '%s' parser. Should be '%s'." % (root_element.get_xmlns(), root_tag, namespace))
        if root_element.tag != root_tag:
            raise AttributeError("Root tag '%s' submitted to '%s' parser. Should be '%s'." % (root_element.tag, root_tag, root_tag))

        smartforward_children = root_element.get_children()

        status = None

        for element in smartforward_children:
            if element.tag == "Status":
                status = element.text
        return status
