package org.jbei.ice.client.collection.add.form;

import java.util.HashMap;

import org.jbei.ice.shared.dto.entry.EntryInfo;
import org.jbei.ice.shared.dto.user.PreferenceKey;

import com.google.gwt.event.dom.client.ClickHandler;
import com.google.gwt.user.client.ui.FocusWidget;
import com.google.gwt.user.client.ui.Widget;

/**
 * Interface for entry form submissions
 *
 * @author Hector Plahar
 */

public interface IEntryFormSubmit {

    void addSubmitHandler(ClickHandler handler);

    void addCancelHandler(ClickHandler handler);

    FocusWidget validateForm();

    Widget asWidget();

    void populateEntries();

    EntryInfo getEntry();

    void setPreferences(HashMap<PreferenceKey, String> preferences);

    String getHeaderDisplay();
}
