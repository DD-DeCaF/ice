package org.jbei.ice.client.bulkupload;

import java.util.ArrayList;
import java.util.Date;
import java.util.Set;

import org.jbei.ice.client.Delegate;
import org.jbei.ice.client.ServiceDelegate;
import org.jbei.ice.client.bulkupload.model.NewBulkInput;
import org.jbei.ice.client.collection.view.OptionSelect;
import org.jbei.ice.lib.shared.EntryAddType;
import org.jbei.ice.lib.shared.dto.bulkupload.BulkUploadInfo;
import org.jbei.ice.lib.shared.dto.group.UserGroup;

import com.google.gwt.event.dom.client.ClickHandler;
import com.google.gwt.user.client.ui.Widget;
import com.google.gwt.view.client.SingleSelectionModel;

public interface IBulkUploadView {

    Widget asWidget();

    void showFeedback(String msg, boolean isError);

    void setSavedDraftsData(ArrayList<BulkUploadMenuItem> data, String lastSaved, IDeleteMenuHandler handler);

    void setPendingDraftsData(ArrayList<BulkUploadMenuItem> data, IRevertBulkUploadHandler handler);

    SingleSelectionModel<BulkUploadMenuItem> getDraftMenuModel();

    SingleSelectionModel<EntryAddType> getImportCreateModel();

    void setDraftMenuVisibility(boolean visible, boolean isToggleClick);

    void addToggleMenuHandler(ClickHandler handler);

    boolean getMenuVisibility();

    void setToggleMenuVisibility(boolean visible);

    void setSheet(NewBulkInput input, boolean isNew, boolean isValidation);

    void setUpdatingVisibility(boolean visible);

    void setSubmitHandler(ClickHandler submitHandler);

    void setResetHandler(ClickHandler resetHandler);

    SingleSelectionModel<BulkUploadMenuItem> getPendingMenuModel();

    void setApproveHandler(ClickHandler handler);

    String getCreator();

    String getCreatorEmail();

    void setCreatorInformation(String name, String email);

    void updateBulkUploadDraftInfo(BulkUploadInfo result);

    void setDraftName(long id, String name);

    void setDraftNameSetHandler(Delegate<String> handler);

    void setLastUpdated(Date date);

    void setLoading(boolean set);

    void setPermissionGroups(ArrayList<UserGroup> userGroups);

    void setSelectedPermissionGroups(ArrayList<OptionSelect> groups);

    void setPermissionDelegate(ServiceDelegate<Set<UserGroup>> handler);
}
