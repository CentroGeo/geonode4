# -*- coding: utf-8 -*-
#########################################################################
#
# Copyright (C) 2016 OSGeo
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#
#########################################################################

"""Utilities for managing GeoNode resource metadata
"""

# Standard Modules
import logging
import datetime
from lxml import etree

# Geonode functionality
from geonode import GeoNodeException
# OWSLib functionality
from owslib.csw import CswRecord
from owslib.iso import MD_Metadata
from owslib.fgdc import Metadata
from owslib.gm03 import GM03

LOGGER = logging.getLogger(__name__)


def set_metadata(xml):
    """Generate dict of model properties based on XML metadata"""

    # check if document is XML
    try:
        exml = etree.fromstring(xml)
    except Exception as err:
        raise GeoNodeException(
            'Uploaded XML document is not XML: %s' % str(err))

    # check if document is an accepted XML metadata format
    tagname = get_tagname(exml)

    if tagname == 'GetRecordByIdResponse':  # strip CSW element
        LOGGER.info('stripping CSW root element')
        exml = exml.getchildren()[0]
        tagname = get_tagname(exml)

    if tagname == 'MD_Metadata':  # ISO
        identifier, vals, regions, keywords = iso2dict(exml)
    elif tagname == 'metadata':  # FGDC
        identifier, vals, regions, keywords = fgdc2dict(exml)
    elif tagname == 'Record':  # Dublin Core
        identifier, vals, regions, keywords = dc2dict(exml)
    elif tagname == 'TRANSFER':  # GM03
        identifier, vals, regions, keywords = gm032dict(exml)
    else:
        raise RuntimeError('Unsupported metadata format')
    if not vals.get("date"):
        vals["date"] = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

    return [identifier, vals, regions, keywords]


def iso2dict(exml):
    """generate dict of properties from gmd:MD_Metadata"""

    vals = {}
    regions = []
    keywords = []

    mdata = MD_Metadata(exml)
    identifier = mdata.identifier
    vals['language'] = mdata.language or mdata.languagecode or 'eng'
    vals['spatial_representation_type'] = mdata.hierarchy
    vals['date'] = sniff_date(mdata.datestamp)

    if hasattr(mdata, 'identification'):
        vals['title'] = mdata.identification.title
        vals['abstract'] = mdata.identification.abstract
        vals['purpose'] = mdata.identification.purpose
        if mdata.identification.supplementalinformation is not None:
            vals['supplemental_information'] = \
                mdata.identification.supplementalinformation

        vals['temporal_extent_start'] = \
            mdata.identification.temporalextent_start
        vals['temporal_extent_end'] = \
            mdata.identification.temporalextent_end

        if len(mdata.identification.topiccategory) > 0:
            vals['topic_category'] = mdata.identification.topiccategory[0]

        if (hasattr(mdata.identification, 'keywords') and
                len(mdata.identification.keywords) > 0):
            for kw in mdata.identification.keywords:
                if kw['type'] == "place":
                    regions.extend(kw['keywords'])
                else:
                    keywords.extend(kw['keywords'])
        if len(mdata.identification.otherconstraints) > 0:
            vals['constraints_other'] = \
                mdata.identification.otherconstraints[0]

        vals['purpose'] = mdata.identification.purpose

    if mdata.dataquality is not None:
        vals['data_quality_statement'] = mdata.dataquality.lineage

    return [identifier, vals, regions, keywords]


def gm032dict(exml):
    """generate dict of properties from GM03 metadata"""

    vals = {}
    regions = []
    keywords = []

    def get_value_by_language(pt_group, language, pt_type='text'):
        for ptg in pt_group:
            if ptg.language == language:
                if pt_type == 'url':
                    val = ptg.plain_url
                else:  # 'text'
                    val = ptg.plain_text
                return val

    mdata = GM03(exml)

    if hasattr(mdata.data, 'core'):
        data = mdata.data.core
    elif hasattr(mdata.data, 'comprehensive'):
        data = mdata.data.comprehensive

    identifier = data.metadata.file_identifier
    language = data.metadata.language

    # GM03 is English/French/German based.
    # Adjust alpha 2 language code to alpha 3
    if len(language) == 3:
        language_alpha3 = language
    elif len(language) == 2:
        if language == 'en':
            language_alpha3 = 'eng'
        elif language == 'fr':
            language_alpha3 = 'fra'
        elif language == 'de':
            language_alpha3 = 'ger'
        else:
            language_alpha3 = 'eng'
    else:
        language_alpha3 = 'eng'

    vals['language'] = language_alpha3

    vals['spatial_representation_type'] = data.metadata.hierarchy_level[0]
    vals['date'] = data.metadata.date_stamp

    # TODO: include once https://github.com/GeoNode/geonode/issues/1125 is done
    # for dt in data.date:
    #    if dt.date_type == 'modified':
    #        vals['date_modified'] =  data.date.date
    #    elif dt.date_type == 'creation':
    #        vals['date_creation'] =  data.date.date
    #    elif dt.date_type == 'publication':
    #        vals['date_publication'] =  data.date.date
    #    elif dt.date_type == 'revision':
    #        vals['date_revision'] =  data.date.date

    if hasattr(data, 'citation'):
        vals['title'] = get_value_by_language(data.citation.title.pt_group, language)

    if hasattr(data, 'data_identification'):
        vals['abstract'] = get_value_by_language(data.data_identification.abstract.pt_group, language)
        vals['topic_category'] = data.data_identification.topic_category

    # temporal extent
    if hasattr(data, 'temporal_extent'):
        if data.temporal_extent.extent['begin'] is not None and data.temporal_extent.extent['end'] is not None:
            vals['temporal_extent_start'] = data.temporal_extent.extent['begin']
            vals['temporal_extent_end'] = data.temporal_extent.extent['end']

    for kw in data.keywords:
        keywords.append(get_value_by_language(kw.keyword.pt_group, language))

    return [identifier, vals, regions, keywords]


def fgdc2dict(exml):
    """generate dict of properties from FGDC metadata"""

    vals = {}
    regions = []
    keywords = []

    mdata = Metadata(exml)
    identifier = mdata.idinfo.datasetid
    if hasattr(mdata.idinfo, 'citation'):
        if hasattr(mdata.idinfo.citation, 'citeinfo'):
            vals['spatial_representation_type'] = \
                mdata.idinfo.citation.citeinfo['geoform']
            vals['title'] = mdata.idinfo.citation.citeinfo['title']

    if hasattr(mdata.idinfo, 'descript'):
        vals['abstract'] = mdata.idinfo.descript.abstract
        vals['purpose'] = mdata.idinfo.descript.purpose
        if mdata.idinfo.descript.supplinf is not None:
            vals['supplemental_information'] = mdata.idinfo.descript.supplinf

    if hasattr(mdata.idinfo, 'keywords'):
        if mdata.idinfo.keywords.theme:
            for theme in mdata.idinfo.keywords.theme:
                if theme['themekt'] is not None:
                    lowered_themekt = theme['themekt'].lower()

                    # Owslib doesn't support extracting the Topic Category
                    # from FGDC.  So we add support here.
                    # http://www.fgdc.gov/metadata/geospatial-metadata-standards
                    if all(
                        ss in lowered_themekt for ss in [
                            'iso',
                            '19115',
                            'topic']) and any(
                        ss in lowered_themekt for ss in [
                            'category',
                            'categories']):
                        vals['topic_category'] = theme['themekey'][0]

                    keywords.extend(theme['themekey'])

        if mdata.idinfo.keywords.place:
            for place in mdata.idinfo.keywords.place:
                if 'placekey' in place:
                    regions.extend(place['placekey'])

    if hasattr(mdata.idinfo.timeperd, 'timeinfo'):
        if hasattr(mdata.idinfo.timeperd.timeinfo, 'rngdates'):
            vals['temporal_extent_start'] = \
                sniff_date(mdata.idinfo.timeperd.timeinfo.rngdates.begdate)
            vals['temporal_extent_end'] = \
                sniff_date(mdata.idinfo.timeperd.timeinfo.rngdates.enddate)

    vals['constraints_other'] = mdata.idinfo.useconst
    raw_date = mdata.metainfo.metd
    if raw_date is not None:
        vals['date'] = sniff_date(raw_date)

    return [identifier, vals, regions, keywords]


def dc2dict(exml):
    """generate dict of properties from csw:Record"""

    vals = {}
    regions = []
    keywords = []

    mdata = CswRecord(exml)
    identifier = mdata.identifier
    vals['language'] = mdata.language
    vals['spatial_representation_type'] = mdata.type
    keywords = mdata.subjects
    regions = [mdata.spatial]
    vals['temporal_extent_start'] = mdata.temporal
    vals['temporal_extent_end'] = mdata.temporal
    vals['constraints_other'] = mdata.license
    vals['date'] = sniff_date(mdata.modified)
    vals['title'] = mdata.title
    vals['abstract'] = mdata.abstract

    return [identifier, vals, regions, keywords]


def sniff_date(datestr):
    """
    Attempt to parse date into datetime.datetime object

    Possible inputs:

    '20001122'
    '2000-11-22'
    '2000-11-22T11:11:11Z'
    '2000-11-22T'
    """

    dateformats = ('%Y%m%d', '%Y-%m-%d', '%Y-%m-%dT%H:%M:%SZ',
                   '%Y-%m-%dT', '%Y/%m/%d')

    for dfmt in dateformats:
        try:
            return datetime.datetime.strptime(datestr.strip(), dfmt)
        except (AttributeError, ValueError):
            pass


def get_tagname(element):
    """get tagname without namespace"""
    try:
        tagname = element.tag.split('}')[1]
    except IndexError:
        tagname = element.tag
    return tagname
