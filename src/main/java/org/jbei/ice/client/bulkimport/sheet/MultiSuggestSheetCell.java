package org.jbei.ice.client.bulkimport.sheet;

import java.util.ArrayList;

import org.jbei.ice.client.common.widget.MultipleTextBox;

import com.google.gwt.user.client.ui.MultiWordSuggestOracle;
import com.google.gwt.user.client.ui.SuggestBox;

/**
 * @author Hector Plahar
 */
public class MultiSuggestSheetCell extends SheetCell {

    protected final MultiWordSuggestOracle oracle;
    protected final SuggestBox box;
    protected final MultipleTextBox textBox;

    public MultiSuggestSheetCell() {
        super();

        oracle = new MultiWordSuggestOracle();
        textBox = new MultipleTextBox();
        box = new SuggestBox(oracle, textBox);
        box.setStyleName("cell_input");

        initWidget(box);
    }

    @Override
    public void setText(String text) {
        box.setText(text);
    }

    /**
     * Sets data for row specified in the param
     * 
     * @param row current row user is working on
     * @return display for user entered value
     */
    @Override
    public String setDataForRow(int row) {
        String ret = textBox.getWholeText();
        setWidgetValue(row, ret, ret);
        box.setText("");
        return ret;
    }

    @Override
    public void setFocus() {
        textBox.setFocus(true);
    }

    /**
     * Adds the suggestions that will be presented to user to oracle
     * 
     * @param data list of strings presented to user
     */
    public void addOracleData(ArrayList<String> data) {
        oracle.clear();
        oracle.addAll(data);
    }

    public boolean hasMultiSuggestions() {
        return true;
    }
}