package org.jbei.ice.web.dataProviders;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashSet;

import org.apache.wicket.extensions.markup.html.repeater.util.SortableDataProvider;
import org.apache.wicket.model.IModel;
import org.apache.wicket.model.Model;
import org.jbei.ice.lib.managers.EntryManager;
import org.jbei.ice.lib.models.Account;
import org.jbei.ice.lib.models.Entry;

public class UserEntriesDataProvider extends SortableDataProvider<Entry> {
    private static final long serialVersionUID = 1L;

    private Account account;
    private ArrayList<Entry> entries = new ArrayList<Entry>();

    public UserEntriesDataProvider(Account account) {
        super();

        this.account = account;
    }

    public Iterator<Entry> iterator(int first, int count) {
        entries.clear();

        try {
            LinkedHashSet<Entry> results = (LinkedHashSet<Entry>) EntryManager.getByAccount(
                    account, first, count);

            for (Entry entry : results) {
                entries.add(entry);
            }
        } catch (Exception e) {
            System.out.println(e.toString());
        }

        return entries.iterator();
    }

    public IModel<Entry> model(Entry object) {
        return new Model<Entry>(object);
    }

    public int size() {
        return EntryManager.getByAccountCount(account);
    }

    public ArrayList<Entry> getEntries() {
        return entries;
    }
}