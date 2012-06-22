package org.jbei.ice.server;

import org.jbei.ice.lib.entry.model.ArabidopsisSeed;
import org.jbei.ice.lib.entry.model.Entry;
import org.jbei.ice.lib.entry.model.EntryFundingSource;
import org.jbei.ice.lib.entry.model.Link;
import org.jbei.ice.lib.entry.model.Name;
import org.jbei.ice.lib.entry.model.Parameter;
import org.jbei.ice.lib.entry.model.Part;
import org.jbei.ice.lib.entry.model.Part.AssemblyStandard;
import org.jbei.ice.lib.entry.model.Plasmid;
import org.jbei.ice.lib.entry.model.Strain;
import org.jbei.ice.lib.models.FundingSource;
import org.jbei.ice.lib.models.SelectionMarker;
import org.jbei.ice.shared.dto.ArabidopsisSeedInfo;
import org.jbei.ice.shared.dto.EntryInfo;
import org.jbei.ice.shared.dto.EntryType;
import org.jbei.ice.shared.dto.ParameterInfo;
import org.jbei.ice.shared.dto.PlasmidInfo;
import org.jbei.ice.shared.dto.StrainInfo;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Factory object for converting data transfer objects to model
 *
 * @author Hector Plahar
 */
public class InfoToModelFactory {

    public static Entry infoToEntry(EntryInfo info) {
        return infoToEntry(info, null);
    }

    /**
     * @param info
     * @param entry if null, a new entry is created otherwise entry is used
     * @return
     */
    public static Entry infoToEntry(EntryInfo info, Entry entry) {

        EntryType type = info.getType();

        switch (type) {
            case PLASMID:
                Plasmid plasmid;
                if (entry == null) {
                    plasmid = new Plasmid();
                    entry = plasmid;
                } else
                    plasmid = (Plasmid) entry;

                plasmid.setRecordType(EntryType.PLASMID.getName());
                PlasmidInfo plasmidInfo = (PlasmidInfo) info;

                plasmid.setBackbone(plasmidInfo.getBackbone());
                plasmid.setOriginOfReplication(plasmidInfo.getOriginOfReplication());
                plasmid.setPromoters(plasmidInfo.getPromoters());
                plasmid.setCircular(plasmidInfo.getCircular());

                break;

            case STRAIN:
                Strain strain;
                if (entry == null) {
                    strain = new Strain();
                    entry = strain;
                } else
                    strain = (Strain) entry;

                strain.setRecordType(EntryType.STRAIN.getName());
                StrainInfo strainInfo = (StrainInfo) info;

                strain.setHost(strainInfo.getHost());
                strain.setGenotypePhenotype(strainInfo.getGenotypePhenotype());
                strain.setPlasmids(strainInfo.getPlasmids());

                entry = strain;
                break;

            case PART:
                Part part;
                if (entry == null) {
                    part = new Part();
                    entry = part;
                } else
                    part = (Part) entry;
                part.setRecordType(EntryType.PART.getName());

                // default is RAW until sequence is supplied.
                part.setPackageFormat(AssemblyStandard.RAW);

                entry = part;
                break;

            case ARABIDOPSIS:
                ArabidopsisSeed seed;
                if (entry == null) {
                    seed = new ArabidopsisSeed();
                    entry = seed;
                } else
                    seed = (ArabidopsisSeed) entry;

                seed.setRecordType(EntryType.ARABIDOPSIS.getName());
                ArabidopsisSeedInfo seedInfo = (ArabidopsisSeedInfo) info;

                seed.setHomozygosity(seedInfo.getHomozygosity());
                seed.setHarvestDate(seedInfo.getHarvestDate());
                seed.setEcotype(seedInfo.getEcotype());
                seed.setParents(seedInfo.getParents());

                if (seedInfo.getGeneration() != null) {
                    ArabidopsisSeed.Generation generation = ArabidopsisSeed.Generation.valueOf(seedInfo.getGeneration()
                                                                                                       .name());
                    seed.setGeneration(generation);
                }

                if (seedInfo.getPlantType() != null) {
                    ArabidopsisSeed.PlantType plantType = ArabidopsisSeed.PlantType.valueOf(seedInfo.getPlantType()
                                                                                                    .name());
                    seed.setPlantType(plantType);
                }

                entry = seed;
                break;

            default:
                return null;
        }

        entry = setCommon(entry, info);
        return entry;
    }

    private static Entry setCommon(Entry entry, EntryInfo info) {
        if (entry == null || info == null)
            return null;

        HashSet<Name> names = getNames(info.getName(), entry);
        entry.setNames(names);
        HashSet<SelectionMarker> markers = getSelectionMarkers(info.getSelectionMarkers(), entry);
        entry.setSelectionMarkers(markers);
        entry.setOwner(info.getOwner());
        entry.setReferences(info.getReferences());
        entry.setRecordId(info.getRecordId());
        entry.setOwnerEmail(info.getOwnerEmail());
        entry.setCreator(info.getCreator());
        entry.setCreatorEmail(info.getCreatorEmail());
        entry.setStatus(info.getStatus() == null ? "" : info.getStatus());
        entry.setAlias(info.getAlias());
        entry.setBioSafetyLevel(info.getBioSafetyLevel() == null ? new Integer(0) : info.getBioSafetyLevel());
        entry.setShortDescription(info.getShortDescription());
        entry.setLongDescription(info.getLongDescription());
        entry.setLongDescriptionType(info.getLongDescriptionType() != null ? info.getLongDescriptionType() : "text");
        entry.setIntellectualProperty(info.getIntellectualProperty());
        entry.setVersionId(info.getVersionId());
        HashSet<Link> links = getLinks(info.getLinks(), entry);
        entry.setLinks(links);

        FundingSource fundingSource = new FundingSource();
        fundingSource.setFundingSource((info.getFundingSource() != null) ? info.getFundingSource()
                                               : "");
        fundingSource.setPrincipalInvestigator(info.getPrincipalInvestigator());
        EntryFundingSource newEntryFundingSource = new EntryFundingSource();
        newEntryFundingSource.setEntry(entry);
        newEntryFundingSource.setFundingSource(fundingSource);
        Set<EntryFundingSource> entryFundingSources = new LinkedHashSet<EntryFundingSource>();
        entryFundingSources.add(newEntryFundingSource);
        entry.setEntryFundingSources(entryFundingSources);

        // parameters 
        List<Parameter> parameters = getParameters(info.getParameters(), entry);
        entry.setParameters(parameters);

        return entry;
    }

    private static List<Parameter> getParameters(ArrayList<ParameterInfo> infos, Entry entry) {
        List<Parameter> parameters = new ArrayList<Parameter>();

        if (infos == null)
            return parameters;

        for (ParameterInfo info : infos) {
            Parameter param = new Parameter();
            Parameter.ParameterType type = Parameter.ParameterType.valueOf(info.getType().name());
            param.setParameterType(type);
            param.setEntry(entry);
            param.setKey(info.getName());
            param.setValue(info.getValue());
            parameters.add(param);
        }
        return parameters;
    }

    private static HashSet<SelectionMarker> getSelectionMarkers(String markerStr, Entry entry) {

        HashSet<SelectionMarker> markers = new HashSet<SelectionMarker>();

        if (markerStr != null && !markerStr.isEmpty()) {
            String[] itemsAsString = markerStr.split("\\s*,+\\s*");

            for (int i = 0; i < itemsAsString.length; i++) {
                String currentItem = itemsAsString[i];
                if (!currentItem.trim().isEmpty()) {
                    SelectionMarker marker = new SelectionMarker();
                    marker.setName(currentItem);
                    marker.setEntry(entry);
                    markers.add(marker);
                }
            }
        }

        return markers;
    }

    private static HashSet<Link> getLinks(String linkString, Entry entry) {
        HashSet<Link> links = new HashSet<Link>();

        if (linkString != null && !linkString.isEmpty()) {
            String[] itemsAsString = linkString.split("\\s*,+\\s*");

            for (int i = 0; i < itemsAsString.length; i++) {
                String currentItem = itemsAsString[i];
                if (!currentItem.trim().isEmpty()) {
                    Link link = new Link();
                    link.setLink(currentItem);
                    link.setEntry(entry);
                    links.add(link);
                }
            }
        }

        return links;
    }

    private static HashSet<Name> getNames(String nameStr, Entry entry) {
        HashSet<Name> names = new HashSet<Name>();
        if (nameStr == null || nameStr.isEmpty())
            return names;

        String[] items = nameStr.split("\\s*,+\\s*");
        for (String item : items) {
            if (!item.isEmpty()) {
                Name name = new Name();
                name.setName(item);
                name.setEntry(entry);
                names.add(name);
            }
        }

        return names;
    }
}
