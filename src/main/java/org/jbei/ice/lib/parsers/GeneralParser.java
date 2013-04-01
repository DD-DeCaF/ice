package org.jbei.ice.lib.parsers;

import java.util.ArrayList;
import java.util.Iterator;

import org.jbei.ice.lib.parsers.fasta.FastaParser;
import org.jbei.ice.lib.parsers.genbank.IceGenbankParser;
import org.jbei.ice.lib.parsers.sbol.SbolParser;
import org.jbei.ice.lib.vo.IDNASequence;

/**
 * Helper class to set up a list of parsers to iterate over, to try to parse the input file.
 *
 * @author Zinovii Dmytriv, Timothy Ham
 */
public class GeneralParser {
    private static GeneralParser instance = null;
    private final ArrayList<AbstractParser> parsers = new ArrayList<AbstractParser>();

    protected GeneralParser() {
        registerParsers();
    }

    public static GeneralParser getInstance() {
        if (instance == null) {
            instance = new GeneralParser();
        }

        return instance;
    }

    public IDNASequence parse(String sequence) {
        IDNASequence parsedSequence = null;

        for (AbstractParser parser : parsers) {
            try {
                parsedSequence = parser.parse(sequence);
                break;
            } catch (InvalidFormatParserException e) {
                // it's ok
            }
        }

        return parsedSequence;
    }

    public IDNASequence parse(byte[] bytes) {
        IDNASequence parsedSequence = null;

        for (AbstractParser parser : parsers) {
            try {
                parsedSequence = parser.parse(bytes);
                break;
            } catch (InvalidFormatParserException e) {
                // it's ok
            }
        }

        return parsedSequence;
    }

    public Iterator<AbstractParser> parsersIterator() {
        return parsers.iterator();
    }

    public String availableParsersToString() {
        return availableParsersToString(", ");
    }

    public String availableParsersToString(String delimiter) {
        StringBuilder stringBuilder = new StringBuilder();

        Iterator<AbstractParser> iterator = parsersIterator();
        while (iterator.hasNext()) {
            stringBuilder.append(iterator.next().getName());
            if (iterator.hasNext()) {
                stringBuilder.append(delimiter);
            }
        }

        return stringBuilder.toString();
    }

    private void registerParsers() {
        parsers.add(new IceGenbankParser());
        parsers.add(new FastaParser());
        parsers.add(new SbolParser());
        parsers.add(new PlainParser());
    }
}
