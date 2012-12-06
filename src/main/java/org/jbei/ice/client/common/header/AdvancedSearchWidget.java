package org.jbei.ice.client.common.header;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import org.jbei.ice.client.Page;
import org.jbei.ice.client.common.FilterWidget;
import org.jbei.ice.client.common.widget.FAIconType;
import org.jbei.ice.client.common.widget.Icon;
import org.jbei.ice.shared.SearchFilterType;
import org.jbei.ice.shared.dto.EntryType;
import org.jbei.ice.shared.dto.search.EntrySearchFilter;

import com.google.gwt.event.dom.client.ChangeEvent;
import com.google.gwt.event.dom.client.ChangeHandler;
import com.google.gwt.event.dom.client.ClickEvent;
import com.google.gwt.event.dom.client.ClickHandler;
import com.google.gwt.event.logical.shared.ValueChangeEvent;
import com.google.gwt.event.logical.shared.ValueChangeHandler;
import com.google.gwt.http.client.URL;
import com.google.gwt.user.client.History;
import com.google.gwt.user.client.ui.Button;
import com.google.gwt.user.client.ui.CheckBox;
import com.google.gwt.user.client.ui.Composite;
import com.google.gwt.user.client.ui.FlexTable;
import com.google.gwt.user.client.ui.HTML;
import com.google.gwt.user.client.ui.HTMLPanel;
import com.google.gwt.user.client.ui.HasAlignment;
import com.google.gwt.user.client.ui.ListBox;
import com.google.gwt.user.client.ui.Widget;

/**
 * Options widget for search
 *
 * @author Hector Plahar
 */
public class AdvancedSearchWidget extends Composite {

    private final EntryTypeFilterWidget entryTypes;     // entry type filter
    private final Button runSearch;
    private final HTML reset;
    private final FlexTable panel;
    private final FlexTable filterOptionsPanel;
    private int currentRow;
    private ChangeHandler filterSelectionHandler;
    private final HashMap<Integer, FilterRow> rowBox;   // mapping of row->list box
    private final EntrySearchFilter searchFilter;
    private final SearchCompositeBox searchInput;

    public AdvancedSearchWidget(SearchCompositeBox searchInput) {
        panel = new FlexTable();
        panel.setCellPadding(0);
        panel.setCellSpacing(0);
        initWidget(panel);
        panel.setStyleName("bg_white");
        searchFilter = new EntrySearchFilter();
        this.searchInput = searchInput;

        filterSelectionHandler = new FilterOptionChangeHandler();

        // init components
        filterOptionsPanel = new FlexTable();
        filterOptionsPanel.setWidth("100%");
        filterOptionsPanel.setHeight("100%");

        rowBox = new HashMap<Integer, FilterRow>();

        runSearch = new Button("Search");
        reset = new HTML("<b>Reset</b>");
        reset.setStyleName("edit_permissions_label");
        entryTypes = new EntryTypeFilterWidget();

        panel.setWidget(0, 0, entryTypes);
        panel.getFlexCellFormatter().setVerticalAlignment(0, 0, HasAlignment.ALIGN_TOP);
        panel.getFlexCellFormatter().setColSpan(0, 0, 2);
        panel.getFlexCellFormatter().setHeight(0, 0, "23px");

        initializeWidget();
        addResetHandler();
        addSearchHandler();
    }

    private void addSearchHandler() {
        runSearch.addClickHandler(new ClickHandler() {
            @Override
            public void onClick(ClickEvent event) {
                String url = Page.QUERY.getLink() + ";";
                url += URL.encode(searchInput.getQueryString());
                History.newItem(url);
            }
        });
    }

    private void addResetHandler() {
        reset.addClickHandler(new ClickHandler() {
            @Override
            public void onClick(ClickEvent event) {
                initializeWidget();
                searchInput.reset();
            }
        });
    }

    // meant to be called only once to set the options available for searching
    private void initializeWidget() {
        // search filter options
        panel.setWidget(1, 0, filterOptionsPanel);
        panel.getFlexCellFormatter().setVerticalAlignment(1, 0, HasAlignment.ALIGN_TOP);
        panel.getFlexCellFormatter().setColSpan(1, 0, 2);

        panel.setWidget(2, 0, runSearch);
        panel.getFlexCellFormatter().setHorizontalAlignment(2, 0, HasAlignment.ALIGN_RIGHT);
        panel.setWidget(2, 1, reset);
        panel.getFlexCellFormatter().setHorizontalAlignment(2, 1, HasAlignment.ALIGN_CENTER);
        panel.getFlexCellFormatter().setWidth(2, 1, "50px");

        filterOptionsPanel.removeAllRows();

        ListBox filterBox = new ListBox();
        populateListBox(filterBox);
        filterOptionsPanel.setWidget(currentRow, 0, filterBox);
        FilterRow filterRow = new FilterRow();
        filterRow.setBox(filterBox);
        rowBox.put(currentRow, filterRow);
    }

    protected void populateListBox(ListBox options) {
        options.setWidth("140px");
        options.setStyleName("pull_down");
        options.addChangeHandler(this.filterSelectionHandler);

        options.addItem("Select Filter", "");
        for (SearchFilterType type : SearchFilterType.values()) {
            options.addItem(type.displayName(), type.name());
        }
    }

    public void setFilterOperands(Widget operand) {
        filterOptionsPanel.setWidget(currentRow, 1, operand);

        // add filter icon and handler
        Icon icon = new Icon(FAIconType.PLUS_SIGN);
        icon.addStyleName("add_filter_style");
        icon.addDomHandler(new ClickHandler() {
            @Override
            public void onClick(ClickEvent event) {
                currentRow += 1;
                addNewFilter(currentRow);
            }
        }, ClickEvent.getType());
        filterOptionsPanel.setWidget(currentRow, 2, icon);

        // remove filter icon and handler
        Icon removeIcon = new Icon(FAIconType.MINUS_SIGN);
        removeIcon.addStyleName("remove_filter");
        removeIcon.addDomHandler(new ClickHandler() {
            @Override
            public void onClick(ClickEvent event) {
                currentRow -= 1;
                removeFilter(currentRow);
            }
        }, ClickEvent.getType());
        filterOptionsPanel.setWidget(currentRow, 3, removeIcon);
    }

    public EntryType[] getSearchEntryType() {
        ArrayList<String> selected = entryTypes.getSelected();
        EntryType[] types = new EntryType[selected.size()];
        int i = 0;
        for (String select : selected) {
            EntryType type = EntryType.nameToType(select);
            if (type == null)
                continue;

            types[i] = type;
            i += 1;
        }

        return types;
    }

    protected void addNewFilter(int afterRow) {
        ListBox filterBox = new ListBox();
        filterBox.setWidth("140px");
        filterBox.setStyleName("pull_down");
        populateListBox(filterBox);
        filterOptionsPanel.setWidget(afterRow, 0, filterBox);
        FilterRow filterRow = new FilterRow();
        filterRow.setBox(filterBox);
        rowBox.put(afterRow, filterRow);
    }

    protected void removeFilter(int atRow) {
        rowBox.remove(atRow);
    }

    public String getSelectedFilter() {
        final ListBox filterOptions = rowBox.get(currentRow).getBox();
        return filterOptions.getValue(filterOptions.getSelectedIndex());
    }

    //
    // inner classes
    //
    public class EntryTypeFilterWidget extends Composite {

        private final CheckBox allCheck;
        private final CheckBox[] typeChecks;

        public EntryTypeFilterWidget() {

            allCheck = new CheckBox();
            typeChecks = new CheckBox[EntryType.values().length];

            String html =
                    "<span class=\"font-80em;\" style=\"letter-spacing:-1.8px; color:#777\"><b>SEARCH:</b></span> " +
                            "<label "
                            + "style=\"padding-left:10px;\"><span style=\"position:relative; top: 2px; *overflow: " +
                            "hidden\" "
                            + "id=\"all_check\"></span>All</label>";

            for (int i = 0; i < EntryType.values().length; i += 1) {
                typeChecks[i] = new CheckBox();
                html += "<label style=\" padding-left:10px;\"><span style=\"position:relative; top: " +
                        "2px; *overflow: hidden\" id=\"" + EntryType.values()[i]
                        .getName() + "_check\"></span>" + EntryType.values()[i].getDisplay() + "</label>";
            }

            HTMLPanel htmlPanel = new HTMLPanel(html);
            htmlPanel.setStyleName("font-80em");
            htmlPanel.addStyleName("pad-3");
            initWidget(htmlPanel);

            htmlPanel.add(allCheck, "all_check");

            for (int i = 0; i < EntryType.values().length; i += 1) {
                htmlPanel.add(typeChecks[i], EntryType.values()[i].getName() + "_check");
            }

            addHandlers();

            // all is pre-selected
            allCheck.setValue(Boolean.TRUE, true);
        }

        protected void addHandlers() {
            allCheck.addValueChangeHandler(new CheckBoxHandler(true));
            CheckBoxHandler handler = new CheckBoxHandler(false);
            for (CheckBox box : typeChecks) {
                box.addValueChangeHandler(handler);
            }
        }

        public ArrayList<String> getSelected() {
            ArrayList<String> selected = new ArrayList<String>();

            if (allCheck.getValue().booleanValue()) {
                for (EntryType type : EntryType.values()) {
                    selected.add(type.getName());
                }
            } else {
                for (int i = 0; i < EntryType.values().length; i += 1) {
                    if (typeChecks[i].getValue().booleanValue()) {
                        selected.add(EntryType.values()[i].getName());
                    }
                }
            }

            return selected;
        }

        private class CheckBoxHandler implements ValueChangeHandler<Boolean> {

            private final boolean isAll;

            public CheckBoxHandler(boolean isAll) {
                this.isAll = isAll;
            }

            @Override
            public void onValueChange(ValueChangeEvent<Boolean> event) {
                if (isAll) {
                    for (CheckBox box : typeChecks) {
                        box.setValue(allCheck.getValue(), false);
                    }

                    if (!allCheck.getValue()) {
                        // clear filters
                        for (Map.Entry<Integer, FilterRow> value : rowBox.entrySet()) {
                            value.getValue().getBox().clear();
                            value.getValue().getBox().addItem("No Filters Available");
                        }
                    } else {
                        // set filters to all
                        for (Map.Entry<Integer, FilterRow> value : rowBox.entrySet()) {
                            value.getValue().getBox().clear();
                            populateListBox(value.getValue().getBox());
                        }
                    }
                } else {
                    ArrayList<EntryType> selected = new ArrayList<EntryType>();
                    for (int i = 0; i < typeChecks.length; i += 1) {
                        if (typeChecks[i].getValue()) {
                            selected.add(EntryType.values()[i]);
                        }
                    }

                    allCheck.setValue((selected.size() == EntryType.values().length), false);
                    filterOptionsPanel.clear();

                    for (int i = 0; i < rowBox.size(); i += 1) {
                        FilterRow removedRow = rowBox.remove(i);
                        String removedSelected = removedRow.getBox().getValue(removedRow.getBox().getSelectedIndex());
                        ListBox createdBox = createListBoxForEntryType(selected, removedSelected);
                        if (createdBox == null)
                            continue;

                        removedRow.setBox(createdBox);
                        rowBox.put(i, removedRow);
                        filterOptionsPanel.setWidget(i, 0, createdBox);
                        currentRow = i;
                        setFilterOperands(removedRow.getValue());
                    }

                    if (rowBox.isEmpty()) {
                        // initialize
                    }
                }
            }

            private ListBox createListBoxForEntryType(ArrayList<EntryType> selected, String selectedValue) {
                ListBox option = new ListBox();
                option.setWidth("140px");
                option.setStyleName("pull_down");
                option.addItem("Select Filter", "");
                option.addChangeHandler(filterSelectionHandler);

                int i = 0;
//                boolean hasSelection = false;

                // for each of the search filters
                for (SearchFilterType type : SearchFilterType.values()) {
                    // any restrictions
                    boolean add = (type.getEntryRestrictions().length == 0);

                    // check to see if at least one of the remaining selected entry types is found in the
                    // restrictions list for the search filter, then add the filter to that option
                    if (!add) {
                        for (EntryType selectedType : selected) {
                            for (EntryType restrictedType : type.getEntryRestrictions()) {
                                if (selectedType == restrictedType) {
                                    add = true;
                                    break;
                                }
                            }
                            if (add)
                                break;
                        }
                    }

                    // can we add now?
                    if (add) {
                        option.addItem(type.displayName(), type.name());
                        i += 1;
                        if (type.name().equals(selectedValue)) {
                            option.setSelectedIndex(i);
//                            hasSelection = true;
                        }
                    }
                }

//                if (!hasSelection)
//                    return null;
                return option;
            }
        }
    }

    private class FilterOptionChangeHandler implements ChangeHandler {

        @Override
        public void onChange(ChangeEvent event) {
            String value = getSelectedFilter();
            SearchFilterType type = SearchFilterType.filterValueOf(value);
            if (type == null) {
                return;
            }

            FilterWidget currentSelected = searchFilter.getFilterWidget(type);
            setFilterOperands(currentSelected);
        }
    }

    private class FilterRow {

        private ListBox box;
        private FilterWidget value;

        public ListBox getBox() {
            return box;
        }

        public void setBox(ListBox box) {
            this.box = box;
        }

        public FilterWidget getValue() {
            return value;
        }

        public void setValue(FilterWidget value) {
            this.value = value;
        }
    }
}
