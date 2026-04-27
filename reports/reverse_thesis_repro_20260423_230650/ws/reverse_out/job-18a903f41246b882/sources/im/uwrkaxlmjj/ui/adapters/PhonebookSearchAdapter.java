package im.uwrkaxlmjj.ui.adapters;

import android.content.Context;
import android.view.View;
import android.view.ViewGroup;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ContactsController;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.Utilities;
import im.uwrkaxlmjj.phoneformat.PhoneFormat;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.cells.UserCell;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import java.util.ArrayList;
import java.util.Timer;
import java.util.TimerTask;
import org.slf4j.Marker;

/* JADX INFO: loaded from: classes5.dex */
public class PhonebookSearchAdapter extends RecyclerListView.SelectionAdapter {
    private Context mContext;
    private ArrayList<Object> searchResult = new ArrayList<>();
    private ArrayList<CharSequence> searchResultNames = new ArrayList<>();
    private Timer searchTimer;

    public PhonebookSearchAdapter(Context context) {
        this.mContext = context;
    }

    public void search(final String query) {
        try {
            if (this.searchTimer != null) {
                this.searchTimer.cancel();
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
        if (query == null) {
            this.searchResult.clear();
            this.searchResultNames.clear();
            notifyDataSetChanged();
        } else {
            Timer timer = new Timer();
            this.searchTimer = timer;
            timer.schedule(new TimerTask() { // from class: im.uwrkaxlmjj.ui.adapters.PhonebookSearchAdapter.1
                @Override // java.util.TimerTask, java.lang.Runnable
                public void run() {
                    try {
                        PhonebookSearchAdapter.this.searchTimer.cancel();
                        PhonebookSearchAdapter.this.searchTimer = null;
                    } catch (Exception e2) {
                        FileLog.e(e2);
                    }
                    PhonebookSearchAdapter.this.processSearch(query);
                }
            }, 200L, 300L);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void processSearch(final String query) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.adapters.-$$Lambda$PhonebookSearchAdapter$BpXcuPGAomwkdr1ZZZ-rOXf6H5g
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$processSearch$1$PhonebookSearchAdapter(query);
            }
        });
    }

    public /* synthetic */ void lambda$processSearch$1$PhonebookSearchAdapter(final String query) {
        final int currentAccount = UserConfig.selectedAccount;
        final ArrayList<ContactsController.Contact> contactsCopy = new ArrayList<>(ContactsController.getInstance(currentAccount).contactsBook.values());
        final ArrayList<TLRPC.Contact> contactsCopy2 = new ArrayList<>(ContactsController.getInstance(currentAccount).contacts);
        Utilities.searchQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.adapters.-$$Lambda$PhonebookSearchAdapter$mhSeXsCmD8HwNeCdInZukZ5rS-Y
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$0$PhonebookSearchAdapter(query, contactsCopy, contactsCopy2, currentAccount);
            }
        });
    }

    /* JADX WARN: Removed duplicated region for block: B:109:0x028e A[LOOP:3: B:85:0x01fe->B:109:0x028e, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:117:0x0142 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:122:0x0252 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:36:0x00ce  */
    /* JADX WARN: Removed duplicated region for block: B:60:0x013f  */
    /* JADX WARN: Removed duplicated region for block: B:73:0x019e A[LOOP:1: B:29:0x00ab->B:73:0x019e, LOOP_END] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public /* synthetic */ void lambda$null$0$PhonebookSearchAdapter(java.lang.String r22, java.util.ArrayList r23, java.util.ArrayList r24, int r25) {
        /*
            Method dump skipped, instruction units count: 676
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.adapters.PhonebookSearchAdapter.lambda$null$0$PhonebookSearchAdapter(java.lang.String, java.util.ArrayList, java.util.ArrayList, int):void");
    }

    protected void onUpdateSearchResults(String query) {
    }

    private void updateSearchResults(final String query, final ArrayList<Object> users, final ArrayList<CharSequence> names) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.adapters.-$$Lambda$PhonebookSearchAdapter$AeVL8zU_OC39Iv-MbQ_Qix2Py1k
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$updateSearchResults$2$PhonebookSearchAdapter(query, users, names);
            }
        });
    }

    public /* synthetic */ void lambda$updateSearchResults$2$PhonebookSearchAdapter(String query, ArrayList users, ArrayList names) {
        onUpdateSearchResults(query);
        this.searchResult = users;
        this.searchResultNames = names;
        notifyDataSetChanged();
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public int getItemCount() {
        return this.searchResult.size();
    }

    public Object getItem(int i) {
        return this.searchResult.get(i);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
        View view = new UserCell(this.mContext, 8, 0, false);
        ((UserCell) view).setNameTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        return new RecyclerListView.Holder(view);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
        if (holder.getItemViewType() == 0) {
            UserCell userCell = (UserCell) holder.itemView;
            Object object = getItem(position);
            TLRPC.User user = null;
            if (object instanceof ContactsController.Contact) {
                ContactsController.Contact contact = (ContactsController.Contact) object;
                if (contact.user != null) {
                    user = contact.user;
                } else {
                    userCell.setCurrentId(contact.contact_id);
                    userCell.setData(null, this.searchResultNames.get(position), contact.phones.isEmpty() ? "" : PhoneFormat.getInstance().format(contact.phones.get(0)), 0);
                }
            } else {
                user = (TLRPC.User) object;
            }
            if (user != null) {
                userCell.setData(user, this.searchResultNames.get(position), PhoneFormat.getInstance().format(Marker.ANY_NON_NULL_MARKER + user.phone), 0);
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
    public boolean isEnabled(RecyclerView.ViewHolder holder) {
        return true;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public int getItemViewType(int i) {
        return 0;
    }
}
