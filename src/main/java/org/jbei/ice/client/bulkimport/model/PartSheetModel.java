package org.jbei.ice.client.bulkimport.model;

import org.jbei.ice.client.bulkimport.sheet.Header;
import org.jbei.ice.shared.BioSafetyOptions;
import org.jbei.ice.shared.dto.AttachmentInfo;
import org.jbei.ice.shared.dto.EntryInfo;
import org.jbei.ice.shared.dto.PartInfo;
import org.jbei.ice.shared.dto.SequenceAnalysisInfo;

import java.util.ArrayList;

public class PartSheetModel extends SingleInfoSheetModel {

    @Override
    public void createInfo(ArrayList<SheetFieldData[]> data, ArrayList<EntryInfo> entryList) {
        if (entryList == null)
            entryList = new ArrayList<EntryInfo>();
        else
            entryList.clear();

        // for each row
        for (SheetFieldData[] datumArray : data) {

            // each each field
            PartInfo info = new PartInfo();
            for (SheetFieldData datum : datumArray)
                setField(info, datum);
            entryList.add(info);
        }
    }

    public void setField(PartInfo info, SheetFieldData datum) {
        if (datum == null)
            return;

        Header header = datum.getType();
        String value = datum.getValue();

        if (header == null || value == null || value.isEmpty())
            return;

        switch (header) {
            case PI:
                info.setPrincipalInvestigator(value);
                break;

            case FUNDING_SOURCE:
                info.setFundingSource(value);
                break;
            case IP:
                info.setIntellectualProperty(value);
                break;

            case BIOSAFETY:
                Integer optionValue = BioSafetyOptions.intValue(value);
                if (optionValue != null)
                    info.setBioSafetyLevel(optionValue);
                break;

            case NAME:
                info.setName(value);
                break;

            case ALIAS:
                info.setAlias(value);
                break;

            case KEYWORDS:
                info.setKeywords(value);
                break;

            case SUMMARY:
                info.setShortDescription(value);
                break;

            case NOTES:
                info.setLongDescription(value);
                info.setLongDescriptionType("text");
                break;

            case REFERENCES:
                info.setReferences(value);
                break;

            case LINKS:
                info.setLinks(value);
                break;

            case STATUS:
                info.setStatus(value);
                break;

            case SEQ_FILENAME:
                ArrayList<SequenceAnalysisInfo> seq = info.getSequenceAnalysis();
                if (seq == null) {
                    seq = new ArrayList<SequenceAnalysisInfo>();
                    info.setSequenceAnalysis(seq);
                }
                SequenceAnalysisInfo analysisInfo = new SequenceAnalysisInfo();
                analysisInfo.setName(value);
                analysisInfo.setFileId(datum.getId());
                seq.add(analysisInfo);
                info.setHasSequence(true);
                info.setSequenceAnalysis(seq);
                break;

            case ATT_FILENAME:
                ArrayList<AttachmentInfo> attInfo = info.getAttachments();
                if (attInfo == null) {
                    attInfo = new ArrayList<AttachmentInfo>();
                    info.setAttachments(attInfo);
                }

                AttachmentInfo att = new AttachmentInfo();
                att.setFilename(value);
                att.setFileId(datum.getId());
                attInfo.add(att);
                info.setHasAttachment(true);
                info.setAttachments(attInfo);
                break;
        }
    }
}
