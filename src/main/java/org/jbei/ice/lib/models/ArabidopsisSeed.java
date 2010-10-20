package org.jbei.ice.lib.models;

import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import javax.persistence.PrimaryKeyJoinColumn;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;

@Entity
@PrimaryKeyJoinColumn(name = "entries_id")
@Table(name = "arabidopsis_seed")
public class ArabidopsisSeed extends Entry {

    private static final long serialVersionUID = 1L;

    public enum Generation {
        M0, M1, M2, T0, T1, T2, T3, T4, T5
    }

    @Column(name = "homozygosity", nullable = false)
    private String homozygosity;

    @Column(name = "ecotype", nullable = false)
    private String ecotype;

    @Column(name = "harvest_date")
    @Temporal(TemporalType.TIMESTAMP)
    private Date harvestDate;

    @Column(name = "parents", nullable = false)
    private String parents;

    @Column(name = "generation", nullable = false)
    @Enumerated(EnumType.STRING)
    private Generation generation;

    public static Map<String, String> getGenerationOptionsMap() {
        Map<String, String> resultMap = new LinkedHashMap<String, String>();
        for (Generation generation : Generation.values()) {
            resultMap.put(generation.toString(), generation.toString());
        }

        return resultMap;

    }

    // getters and setters
    public String getHomozygosity() {
        return homozygosity;
    }

    public void setHomozygosity(String homozygosity) {
        this.homozygosity = homozygosity;
    }

    public String getEcotype() {
        return ecotype;
    }

    public void setEcotype(String ecotype) {
        this.ecotype = ecotype;
    }

    public Date getHarvestDate() {
        return harvestDate;
    }

    public void setHarvestDate(Date harvestDate) {
        this.harvestDate = harvestDate;
    }

    public String getParents() {
        return parents;
    }

    public void setParents(String parents) {
        this.parents = parents;
    }

    public Generation getGeneration() {
        return generation;
    }

    public void setGeneration(Generation generation) {
        this.generation = generation;
    }

}