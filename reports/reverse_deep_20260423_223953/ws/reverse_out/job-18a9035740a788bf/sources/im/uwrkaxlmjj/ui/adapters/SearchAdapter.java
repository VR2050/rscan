package im.uwrkaxlmjj.ui.adapters;

import android.content.Context;
import android.util.SparseArray;
import android.view.View;
import android.view.ViewGroup;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ContactsController;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.Utilities;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.adapters.SearchAdapterHelper;
import im.uwrkaxlmjj.ui.cells.GraySectionCell;
import im.uwrkaxlmjj.ui.cells.ProfileSearchCell;
import im.uwrkaxlmjj.ui.cells.TextCell;
import im.uwrkaxlmjj.ui.cells.UserCell;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Timer;
import java.util.TimerTask;

/* JADX INFO: loaded from: classes5.dex */
public class SearchAdapter extends RecyclerListView.SelectionAdapter {
    private boolean allowBots;
    private boolean allowChats;
    private boolean allowPhoneNumbers;
    private boolean allowUsernameSearch;
    private int channelId;
    private SparseArray<?> checkedMap;
    private SparseArray<TLRPC.User> ignoreUsers;
    private Context mContext;
    private boolean onlyMutual;
    private SearchAdapterHelper searchAdapterHelper;
    private Timer searchTimer;
    private boolean useUserCell;
    private ArrayList<TLObject> searchResult = new ArrayList<>();
    private ArrayList<CharSequence> searchResultNames = new ArrayList<>();
    private int miViewType = 0;

    public SearchAdapter(Context context, SparseArray<TLRPC.User> arg1, boolean usernameSearch, boolean mutual, boolean chats, boolean bots, boolean phones, int searchChannelId) {
        this.mContext = context;
        this.ignoreUsers = arg1;
        this.onlyMutual = mutual;
        this.allowUsernameSearch = usernameSearch;
        this.allowChats = chats;
        this.allowBots = bots;
        this.channelId = searchChannelId;
        this.allowPhoneNumbers = phones;
        SearchAdapterHelper searchAdapterHelper = new SearchAdapterHelper(true);
        this.searchAdapterHelper = searchAdapterHelper;
        searchAdapterHelper.setDelegate(new SearchAdapterHelper.SearchAdapterHelperDelegate() { // from class: im.uwrkaxlmjj.ui.adapters.SearchAdapter.1
            @Override // im.uwrkaxlmjj.ui.adapters.SearchAdapterHelper.SearchAdapterHelperDelegate
            public void onDataSetChanged() {
                SearchAdapter.this.notifyDataSetChanged();
            }

            @Override // im.uwrkaxlmjj.ui.adapters.SearchAdapterHelper.SearchAdapterHelperDelegate
            public void onSetHashtags(ArrayList<SearchAdapterHelper.HashtagObject> arrayList, HashMap<String, SearchAdapterHelper.HashtagObject> hashMap) {
            }

            @Override // im.uwrkaxlmjj.ui.adapters.SearchAdapterHelper.SearchAdapterHelperDelegate
            public SparseArray<TLRPC.User> getExcludeUsers() {
                return SearchAdapter.this.ignoreUsers;
            }
        });
    }

    public void setCheckedMap(SparseArray<?> map) {
        this.checkedMap = map;
    }

    public void setUseUserCell(boolean value) {
        this.useUserCell = value;
    }

    public void searchDialogs(final String query) {
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
            if (this.allowUsernameSearch) {
                this.searchAdapterHelper.queryServerSearch(null, true, this.allowChats, this.allowBots, true, this.channelId, this.allowPhoneNumbers, 0);
            }
            notifyDataSetChanged();
            return;
        }
        Timer timer = new Timer();
        this.searchTimer = timer;
        timer.schedule(new TimerTask() { // from class: im.uwrkaxlmjj.ui.adapters.SearchAdapter.2
            @Override // java.util.TimerTask, java.lang.Runnable
            public void run() {
                try {
                    SearchAdapter.this.searchTimer.cancel();
                    SearchAdapter.this.searchTimer = null;
                } catch (Exception e2) {
                    FileLog.e(e2);
                }
                SearchAdapter.this.processSearch(query);
            }
        }, 200L, 300L);
    }

    public void setMiViewType(int miViewType) {
        this.miViewType = miViewType;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void processSearch(final String query) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.adapters.-$$Lambda$SearchAdapter$SjzNfhcih5GvpVmgvHi_TOw2u_s
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$processSearch$1$SearchAdapter(query);
            }
        });
    }

    public /* synthetic */ void lambda$processSearch$1$SearchAdapter(final String query) {
        if (this.allowUsernameSearch) {
            this.searchAdapterHelper.queryServerSearch(query, true, this.allowChats, this.allowBots, true, this.channelId, this.allowPhoneNumbers, -1);
        }
        final int currentAccount = UserConfig.selectedAccount;
        final ArrayList<TLRPC.Contact> contactsCopy = new ArrayList<>(ContactsController.getInstance(currentAccount).contacts);
        Utilities.searchQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.adapters.-$$Lambda$SearchAdapter$O8Rj3ZQhsA0klAMIvUWTWl8hg4E
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$0$SearchAdapter(query, contactsCopy, currentAccount);
            }
        });
    }

    /* JADX WARN: Removed duplicated region for block: B:58:0x0119 A[LOOP:1: B:38:0x00b0->B:58:0x0119, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:71:0x00dc A[SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public /* synthetic */ void lambda$null$0$SearchAdapter(java.lang.String r18, java.util.ArrayList r19, int r20) {
        /*
            Method dump skipped, instruction units count: 304
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.adapters.SearchAdapter.lambda$null$0$SearchAdapter(java.lang.String, java.util.ArrayList, int):void");
    }

    private void updateSearchResults(final ArrayList<TLObject> users, final ArrayList<CharSequence> names) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.adapters.-$$Lambda$SearchAdapter$CFFabICQXyKuoUs-xA3V6bVYCaw
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$updateSearchResults$2$SearchAdapter(users, names);
            }
        });
    }

    public /* synthetic */ void lambda$updateSearchResults$2$SearchAdapter(ArrayList users, ArrayList names) {
        this.searchResult = users;
        this.searchResultNames = names;
        this.searchAdapterHelper.mergeResults(users);
        notifyDataSetChanged();
    }

    @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
    public boolean isEnabled(RecyclerView.ViewHolder holder) {
        int type = holder.getItemViewType();
        return type == 0 || type == 2;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public int getItemCount() {
        int count = this.searchResult.size();
        int globalCount = this.searchAdapterHelper.getGlobalSearch().size();
        if (globalCount != 0) {
            count += globalCount + 1;
        }
        int phoneCount = this.searchAdapterHelper.getPhoneSearch().size();
        if (phoneCount != 0) {
            return count + phoneCount;
        }
        return count;
    }

    public boolean isGlobalSearch(int i) {
        int localCount = this.searchResult.size();
        int globalCount = this.searchAdapterHelper.getGlobalSearch().size();
        int phoneCount = this.searchAdapterHelper.getPhoneSearch().size();
        if (i >= 0 && i < localCount) {
            return false;
        }
        if ((i > localCount && i < localCount + phoneCount) || i <= localCount + phoneCount || i > globalCount + phoneCount + localCount) {
            return false;
        }
        return true;
    }

    public Object getItem(int i) {
        int localCount = this.searchResult.size();
        int globalCount = this.searchAdapterHelper.getGlobalSearch().size();
        int phoneCount = this.searchAdapterHelper.getPhoneSearch().size();
        if (i >= 0 && i < localCount) {
            return this.searchResult.get(i);
        }
        int i2 = i - localCount;
        if (i2 >= 0 && i2 < phoneCount) {
            return this.searchAdapterHelper.getPhoneSearch().get(i2);
        }
        int i3 = i2 - phoneCount;
        if (i3 > 0 && i3 <= globalCount) {
            return this.searchAdapterHelper.getGlobalSearch().get(i3 - 1);
        }
        return null;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
        View view;
        if (viewType != 0) {
            if (viewType == 1) {
                view = new GraySectionCell(this.mContext);
            } else {
                view = new TextCell(this.mContext, 16);
            }
        } else {
            if (this.useUserCell) {
                view = new UserCell(this.mContext, 1, 1, false);
                if (this.checkedMap != null) {
                    ((UserCell) view).setChecked(false, false);
                }
            } else {
                view = new ProfileSearchCell(this.mContext);
            }
            view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
        }
        return new RecyclerListView.Holder(view);
    }

    /* JADX WARN: Removed duplicated region for block: B:49:0x013a A[PHI: r8
      0x013a: PHI (r8v7 java.lang.CharSequence) = 
      (r8v6 java.lang.CharSequence)
      (r8v6 java.lang.CharSequence)
      (r8v17 java.lang.CharSequence)
      (r8v17 java.lang.CharSequence)
      (r8v17 java.lang.CharSequence)
      (r8v17 java.lang.CharSequence)
     binds: [B:33:0x00e8, B:34:0x00ea, B:25:0x00ba, B:26:0x00bc, B:28:0x00c2, B:30:0x00db] A[DONT_GENERATE, DONT_INLINE]] */
    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void onBindViewHolder(androidx.recyclerview.widget.RecyclerView.ViewHolder r19, int r20) {
        /*
            Method dump skipped, instruction units count: 503
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.adapters.SearchAdapter.onBindViewHolder(androidx.recyclerview.widget.RecyclerView$ViewHolder, int):void");
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public int getItemViewType(int i) {
        Object item = getItem(i);
        if (item == null) {
            return 1;
        }
        if (item instanceof String) {
            String str = (String) item;
            if ("section".equals(str)) {
                return 1;
            }
            return 2;
        }
        return 0;
    }
}
