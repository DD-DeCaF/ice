package org.jbei.ice.client.search.blast;

import java.util.LinkedList;

import org.jbei.ice.client.RegistryServiceAsync;
import org.jbei.ice.client.common.HasEntryDataViewDataProvider;
import org.jbei.ice.client.common.table.HasEntryDataTable;
import org.jbei.ice.shared.ColumnField;
import org.jbei.ice.shared.dto.entry.EntryInfo;
import org.jbei.ice.shared.dto.entry.HasEntryInfo;
import org.jbei.ice.shared.dto.search.SearchResultInfo;

import com.google.gwt.view.client.Range;

public class BlastSearchDataProvider extends HasEntryDataViewDataProvider<SearchResultInfo> {

    public BlastSearchDataProvider(HasEntryDataTable<SearchResultInfo> view, RegistryServiceAsync service) {
        super(view, service, ColumnField.BIT_SCORE);
    }

    public void setBlastData(LinkedList<SearchResultInfo> data) {
        reset();
        if (data == null) {
            updateRowCount(0, true);
            return;
        }

        results.addAll(data);
        resultSize = data.size();  // todo : need a blastResult object as a wrapper
        updateRowCount(resultSize, true);

        // retrieve the first page of results and updateRowData
        final Range range = this.dataTable.getVisibleRange();
        final int rangeStart = 0;
        int rangeEnd = rangeStart + range.getLength();
        if (rangeEnd > resultSize)
            rangeEnd = resultSize;

        updateRowData(rangeStart, results.subList(rangeStart, rangeEnd));
        dataTable.setPageStart(0);
    }

    @Override
    public EntryInfo getCachedData(long entryId, String recordId) {
        for (HasEntryInfo result : results) {
            EntryInfo info = result.getEntryInfo();
            if (recordId != null && info.getRecordId().equalsIgnoreCase(recordId))
                return info;

            if (info.getId() == entryId)
                return info;
        }
        return null;
    }

    @Override
    public int indexOfCached(EntryInfo info) {
        int i = 0;
        for (HasEntryInfo result : results) {

            if (result.getEntryInfo().getId() == info.getId())
                return i;
            i += 1;
        }
        return -1;
    }

    @Override
    public int getSize() {
        return resultSize;
    }

    @Override
    public EntryInfo getNext(EntryInfo info) {
        int idx = indexOfCached(info);
        if (idx == -1)
            return null;
        return results.get(idx + 1).getEntryInfo();
    }

    @Override
    public EntryInfo getPrev(EntryInfo info) {
        int idx = indexOfCached(info);
        if (idx == -1)
            return null;
        return results.get(idx - 1).getEntryInfo();
    }

    @Override
    protected void fetchEntryData(ColumnField field, boolean ascending, int start, int factor, boolean reset) {
        //To change body of implemented methods use File | Settings | File Templates.
        // TODO
    }
}
