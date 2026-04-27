package im.uwrkaxlmjj.ui.adapters;

import android.content.Context;
import android.text.TextUtils;
import android.util.LongSparseArray;
import android.util.SparseArray;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.DispatchQueue;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.MediaDataController;
import im.uwrkaxlmjj.messenger.MessageObject;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.MessagesStorage;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.UserObject;
import im.uwrkaxlmjj.messenger.Utilities;
import im.uwrkaxlmjj.sqlite.SQLiteCursor;
import im.uwrkaxlmjj.sqlite.SQLitePreparedStatement;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.adapters.DialogsSearchAdapter;
import im.uwrkaxlmjj.ui.adapters.SearchAdapterHelper;
import im.uwrkaxlmjj.ui.cells.DialogCell;
import im.uwrkaxlmjj.ui.cells.GraySectionCell;
import im.uwrkaxlmjj.ui.cells.HashtagSearchCell;
import im.uwrkaxlmjj.ui.cells.HintDialogCell;
import im.uwrkaxlmjj.ui.cells.LoadingCell;
import im.uwrkaxlmjj.ui.cells.ProfileSearchCell;
import im.uwrkaxlmjj.ui.cells.TextCell;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;

/* JADX INFO: loaded from: classes5.dex */
public class DialogsSearchAdapter extends RecyclerListView.SelectionAdapter {
    private int currentAccount;
    private DialogsSearchAdapterDelegate delegate;
    private int dialogsType;
    private RecyclerListView innerListView;
    private String lastMessagesSearchString;
    private int lastReqId;
    private int lastSearchId;
    private String lastSearchText;
    private Context mContext;
    private int mProfileSearchCellMarginRight;
    private boolean messagesSearchEndReached;
    private int needMessagesSearch;
    private int nextSearchRate;
    private ArrayList<RecentSearchObject> recentSearchObjects;
    private LongSparseArray<RecentSearchObject> recentSearchObjectsById;
    private int reqId;
    private SearchAdapterHelper searchAdapterHelper;
    private ArrayList<TLObject> searchResult;
    private ArrayList<String> searchResultHashtags;
    private ArrayList<MessageObject> searchResultMessages;
    private ArrayList<CharSequence> searchResultNames;
    private Runnable searchRunnable;
    private Runnable searchRunnable2;
    private boolean searchWas;
    private int selfUserId;

    public interface DialogsSearchAdapterDelegate {
        void didPressedOnSubDialog(long j);

        void needClearList();

        void needRemoveHint(int i);

        void searchStateChanged(boolean z);
    }

    /* JADX INFO: Access modifiers changed from: private */
    class DialogSearchResult {
        public int date;
        public CharSequence name;
        public TLObject object;

        private DialogSearchResult() {
        }
    }

    protected static class RecentSearchObject {
        int date;
        long did;
        TLObject object;

        protected RecentSearchObject() {
        }
    }

    private class CategoryAdapterRecycler extends RecyclerListView.SelectionAdapter {
        private CategoryAdapterRecycler() {
        }

        public void setIndex(int value) {
            notifyDataSetChanged();
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view = new HintDialogCell(DialogsSearchAdapter.this.mContext);
            view.setLayoutParams(new RecyclerView.LayoutParams(AndroidUtilities.dp(80.0f), AndroidUtilities.dp(86.0f)));
            return new RecyclerListView.Holder(view);
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            return true;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            HintDialogCell cell = (HintDialogCell) holder.itemView;
            TLRPC.TL_topPeer peer = MediaDataController.getInstance(DialogsSearchAdapter.this.currentAccount).hints.get(position);
            new TLRPC.TL_dialog();
            TLRPC.Chat chat = null;
            TLRPC.User user = null;
            int did = 0;
            if (peer.peer.user_id != 0) {
                did = peer.peer.user_id;
                user = MessagesController.getInstance(DialogsSearchAdapter.this.currentAccount).getUser(Integer.valueOf(peer.peer.user_id));
            } else if (peer.peer.channel_id != 0) {
                did = -peer.peer.channel_id;
                chat = MessagesController.getInstance(DialogsSearchAdapter.this.currentAccount).getChat(Integer.valueOf(peer.peer.channel_id));
            } else if (peer.peer.chat_id != 0) {
                did = -peer.peer.chat_id;
                chat = MessagesController.getInstance(DialogsSearchAdapter.this.currentAccount).getChat(Integer.valueOf(peer.peer.chat_id));
            }
            cell.setTag(Integer.valueOf(did));
            String name = "";
            if (user != null) {
                name = UserObject.getFirstName(user);
            } else if (chat != null) {
                name = chat.title;
            }
            cell.setDialog(did, true, name);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            return MediaDataController.getInstance(DialogsSearchAdapter.this.currentAccount).hints.size();
        }
    }

    public DialogsSearchAdapter(Context context, int messagesSearch, int type) {
        this(context, messagesSearch, type, 0);
    }

    public DialogsSearchAdapter(Context context, int messagesSearch, int type, int profileSearchCellMarginRight) {
        this.searchResult = new ArrayList<>();
        this.searchResultNames = new ArrayList<>();
        this.searchResultMessages = new ArrayList<>();
        this.searchResultHashtags = new ArrayList<>();
        this.reqId = 0;
        this.lastSearchId = 0;
        this.currentAccount = UserConfig.selectedAccount;
        this.recentSearchObjects = new ArrayList<>();
        this.recentSearchObjectsById = new LongSparseArray<>();
        SearchAdapterHelper searchAdapterHelper = new SearchAdapterHelper(false);
        this.searchAdapterHelper = searchAdapterHelper;
        searchAdapterHelper.setDelegate(new SearchAdapterHelper.SearchAdapterHelperDelegate() { // from class: im.uwrkaxlmjj.ui.adapters.DialogsSearchAdapter.1
            @Override // im.uwrkaxlmjj.ui.adapters.SearchAdapterHelper.SearchAdapterHelperDelegate
            public /* synthetic */ SparseArray<TLRPC.User> getExcludeUsers() {
                return SearchAdapterHelper.SearchAdapterHelperDelegate.CC.$default$getExcludeUsers(this);
            }

            @Override // im.uwrkaxlmjj.ui.adapters.SearchAdapterHelper.SearchAdapterHelperDelegate
            public void onDataSetChanged() {
                DialogsSearchAdapter.this.searchWas = true;
                if (!DialogsSearchAdapter.this.searchAdapterHelper.isSearchInProgress() && DialogsSearchAdapter.this.delegate != null) {
                    DialogsSearchAdapter.this.delegate.searchStateChanged(false);
                }
                DialogsSearchAdapter.this.notifyDataSetChanged();
            }

            @Override // im.uwrkaxlmjj.ui.adapters.SearchAdapterHelper.SearchAdapterHelperDelegate
            public void onSetHashtags(ArrayList<SearchAdapterHelper.HashtagObject> arrayList, HashMap<String, SearchAdapterHelper.HashtagObject> hashMap) {
                for (int a = 0; a < arrayList.size(); a++) {
                    DialogsSearchAdapter.this.searchResultHashtags.add(arrayList.get(a).hashtag);
                }
                if (DialogsSearchAdapter.this.delegate != null) {
                    DialogsSearchAdapter.this.delegate.searchStateChanged(false);
                }
                DialogsSearchAdapter.this.notifyDataSetChanged();
            }
        });
        this.mContext = context;
        this.needMessagesSearch = messagesSearch;
        this.dialogsType = type;
        this.selfUserId = UserConfig.getInstance(this.currentAccount).getClientUserId();
        loadRecentSearch();
        MediaDataController.getInstance(this.currentAccount).loadHints(true);
        this.mProfileSearchCellMarginRight = profileSearchCellMarginRight;
    }

    public RecyclerListView getInnerListView() {
        return this.innerListView;
    }

    public void setDelegate(DialogsSearchAdapterDelegate delegate) {
        this.delegate = delegate;
    }

    public boolean isMessagesSearchEndReached() {
        return this.messagesSearchEndReached;
    }

    public void loadMoreSearchMessages() {
        searchMessagesInternal(this.lastMessagesSearchString);
    }

    public String getLastSearchString() {
        return this.lastMessagesSearchString;
    }

    private void searchMessagesInternal(String query) {
        if (this.needMessagesSearch != 0) {
            if (TextUtils.isEmpty(this.lastMessagesSearchString) && TextUtils.isEmpty(query)) {
                return;
            }
            if (this.reqId != 0) {
                ConnectionsManager.getInstance(this.currentAccount).cancelRequest(this.reqId, true);
                this.reqId = 0;
            }
            if (TextUtils.isEmpty(query)) {
                this.searchResultMessages.clear();
                this.lastReqId = 0;
                this.lastMessagesSearchString = null;
                this.searchWas = false;
                notifyDataSetChanged();
                DialogsSearchAdapterDelegate dialogsSearchAdapterDelegate = this.delegate;
                if (dialogsSearchAdapterDelegate != null) {
                    dialogsSearchAdapterDelegate.searchStateChanged(false);
                }
            }
        }
    }

    public boolean hasRecentRearch() {
        int i = this.dialogsType;
        return (i == 4 || i == 5 || i == 6 || (this.recentSearchObjects.isEmpty() && MediaDataController.getInstance(this.currentAccount).hints.isEmpty())) ? false : true;
    }

    public boolean isRecentSearchDisplayed() {
        int i;
        return (this.needMessagesSearch == 2 || this.searchWas || (this.recentSearchObjects.isEmpty() && MediaDataController.getInstance(this.currentAccount).hints.isEmpty()) || (i = this.dialogsType) == 4 || i == 5 || i == 6) ? false : true;
    }

    public void loadRecentSearch() {
        MessagesStorage.getInstance(this.currentAccount).getStorageQueue().postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.adapters.-$$Lambda$DialogsSearchAdapter$LconswwP9N5lIJhhBUEI97SY6vU
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$loadRecentSearch$2$DialogsSearchAdapter();
            }
        });
    }

    public /* synthetic */ void lambda$loadRecentSearch$2$DialogsSearchAdapter() {
        ArrayList<Integer> chatsToLoad;
        try {
            int i = 0;
            SQLiteCursor cursor = MessagesStorage.getInstance(this.currentAccount).getDatabase().queryFinalized("SELECT did, date FROM search_recent WHERE 1", new Object[0]);
            ArrayList<Integer> usersToLoad = new ArrayList<>();
            ArrayList<Integer> chatsToLoad2 = new ArrayList<>();
            ArrayList<Integer> encryptedToLoad = new ArrayList<>();
            new ArrayList();
            final ArrayList<RecentSearchObject> arrayList = new ArrayList<>();
            final LongSparseArray<RecentSearchObject> hashMap = new LongSparseArray<>();
            while (cursor.next()) {
                long did = cursor.longValue(i);
                boolean add = false;
                int lower_id = (int) did;
                int high_id = (int) (did >> 32);
                if (lower_id != 0) {
                    if (lower_id > 0) {
                        if (this.dialogsType != 2 && !usersToLoad.contains(Integer.valueOf(lower_id))) {
                            usersToLoad.add(Integer.valueOf(lower_id));
                            add = true;
                        }
                    } else if (!chatsToLoad2.contains(Integer.valueOf(-lower_id))) {
                        chatsToLoad2.add(Integer.valueOf(-lower_id));
                        add = true;
                    }
                } else if ((this.dialogsType == 0 || this.dialogsType == 3) && !encryptedToLoad.contains(Integer.valueOf(high_id))) {
                    encryptedToLoad.add(Integer.valueOf(high_id));
                    add = true;
                }
                if (!add) {
                    chatsToLoad = chatsToLoad2;
                } else {
                    RecentSearchObject recentSearchObject = new RecentSearchObject();
                    recentSearchObject.did = did;
                    recentSearchObject.date = cursor.intValue(1);
                    arrayList.add(recentSearchObject);
                    chatsToLoad = chatsToLoad2;
                    hashMap.put(recentSearchObject.did, recentSearchObject);
                }
                chatsToLoad2 = chatsToLoad;
                i = 0;
            }
            ArrayList<Integer> chatsToLoad3 = chatsToLoad2;
            cursor.dispose();
            ArrayList<TLRPC.User> users = new ArrayList<>();
            if (!encryptedToLoad.isEmpty()) {
                ArrayList<TLRPC.EncryptedChat> encryptedChats = new ArrayList<>();
                MessagesStorage.getInstance(this.currentAccount).getEncryptedChatsInternal(TextUtils.join(",", encryptedToLoad), encryptedChats, usersToLoad);
                for (int a = 0; a < encryptedChats.size(); a++) {
                    hashMap.get(((long) encryptedChats.get(a).id) << 32).object = encryptedChats.get(a);
                }
            }
            if (!chatsToLoad3.isEmpty()) {
                ArrayList<TLRPC.Chat> chats = new ArrayList<>();
                MessagesStorage.getInstance(this.currentAccount).getChatsInternal(TextUtils.join(",", chatsToLoad3), chats);
                for (int a2 = 0; a2 < chats.size(); a2++) {
                    TLRPC.Chat chat = chats.get(a2);
                    long did2 = -chat.id;
                    if (chat.migrated_to != null) {
                        RecentSearchObject recentSearchObject2 = hashMap.get(did2);
                        hashMap.remove(did2);
                        if (recentSearchObject2 != null) {
                            arrayList.remove(recentSearchObject2);
                        }
                    } else {
                        hashMap.get(did2).object = chat;
                    }
                }
            }
            if (!usersToLoad.isEmpty()) {
                MessagesStorage.getInstance(this.currentAccount).getUsersInternal(TextUtils.join(",", usersToLoad), users);
                for (int a3 = 0; a3 < users.size(); a3++) {
                    TLRPC.User user = users.get(a3);
                    RecentSearchObject recentSearchObject3 = hashMap.get(user.id);
                    if (recentSearchObject3 != null) {
                        recentSearchObject3.object = user;
                    }
                }
            }
            Collections.sort(arrayList, new Comparator() { // from class: im.uwrkaxlmjj.ui.adapters.-$$Lambda$DialogsSearchAdapter$9o4UhvGqJDuq06x8mvSK2qFcE7A
                @Override // java.util.Comparator
                public final int compare(Object obj, Object obj2) {
                    return DialogsSearchAdapter.lambda$null$0((DialogsSearchAdapter.RecentSearchObject) obj, (DialogsSearchAdapter.RecentSearchObject) obj2);
                }
            });
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.adapters.-$$Lambda$DialogsSearchAdapter$sSLpO5z21ChKrt3AGqSKRujKqhw
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$1$DialogsSearchAdapter(arrayList, hashMap);
                }
            });
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    static /* synthetic */ int lambda$null$0(RecentSearchObject lhs, RecentSearchObject rhs) {
        if (lhs.date < rhs.date) {
            return 1;
        }
        if (lhs.date > rhs.date) {
            return -1;
        }
        return 0;
    }

    public void putRecentSearch(final long did, TLObject object) {
        RecentSearchObject recentSearchObject = this.recentSearchObjectsById.get(did);
        if (recentSearchObject == null) {
            recentSearchObject = new RecentSearchObject();
            this.recentSearchObjectsById.put(did, recentSearchObject);
        } else {
            this.recentSearchObjects.remove(recentSearchObject);
        }
        this.recentSearchObjects.add(0, recentSearchObject);
        recentSearchObject.did = did;
        recentSearchObject.object = object;
        recentSearchObject.date = (int) (System.currentTimeMillis() / 1000);
        notifyDataSetChanged();
        MessagesStorage.getInstance(this.currentAccount).getStorageQueue().postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.adapters.-$$Lambda$DialogsSearchAdapter$UEt2hSNPCpHy10H9ZgWkGtTH8RM
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$putRecentSearch$3$DialogsSearchAdapter(did);
            }
        });
    }

    public /* synthetic */ void lambda$putRecentSearch$3$DialogsSearchAdapter(long did) {
        try {
            SQLitePreparedStatement state = MessagesStorage.getInstance(this.currentAccount).getDatabase().executeFast("REPLACE INTO search_recent VALUES(?, ?)");
            state.requery();
            state.bindLong(1, did);
            state.bindInteger(2, (int) (System.currentTimeMillis() / 1000));
            state.step();
            state.dispose();
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public void clearRecentSearch() {
        this.recentSearchObjectsById = new LongSparseArray<>();
        this.recentSearchObjects = new ArrayList<>();
        notifyDataSetChanged();
        MessagesStorage.getInstance(this.currentAccount).getStorageQueue().postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.adapters.-$$Lambda$DialogsSearchAdapter$aoH8VGvw3GaajOhavYLy1lNX1J0
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$clearRecentSearch$4$DialogsSearchAdapter();
            }
        });
    }

    public /* synthetic */ void lambda$clearRecentSearch$4$DialogsSearchAdapter() {
        try {
            MessagesStorage.getInstance(this.currentAccount).getDatabase().executeFast("DELETE FROM search_recent WHERE 1").stepThis().dispose();
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public void addHashtagsFromMessage(CharSequence message) {
        this.searchAdapterHelper.addHashtagsFromMessage(message);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX INFO: renamed from: setRecentSearch, reason: merged with bridge method [inline-methods] */
    public void lambda$null$1$DialogsSearchAdapter(ArrayList<RecentSearchObject> arrayList, LongSparseArray<RecentSearchObject> hashMap) {
        this.recentSearchObjects = arrayList;
        this.recentSearchObjectsById = hashMap;
        for (int a = 0; a < this.recentSearchObjects.size(); a++) {
            RecentSearchObject recentSearchObject = this.recentSearchObjects.get(a);
            if (recentSearchObject.object instanceof TLRPC.User) {
                MessagesController.getInstance(this.currentAccount).putUser((TLRPC.User) recentSearchObject.object, true);
            } else if (recentSearchObject.object instanceof TLRPC.Chat) {
                MessagesController.getInstance(this.currentAccount).putChat((TLRPC.Chat) recentSearchObject.object, true);
            } else if (recentSearchObject.object instanceof TLRPC.EncryptedChat) {
                MessagesController.getInstance(this.currentAccount).putEncryptedChat((TLRPC.EncryptedChat) recentSearchObject.object, true);
            }
        }
        notifyDataSetChanged();
    }

    private void searchDialogsInternal(final String query, final int searchId) {
        if (this.needMessagesSearch == 2) {
            return;
        }
        MessagesStorage.getInstance(this.currentAccount).getStorageQueue().postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.adapters.-$$Lambda$DialogsSearchAdapter$oRNQ_0icC4iVSCA-RjLFTI-lpVs
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$searchDialogsInternal$6$DialogsSearchAdapter(query, searchId);
            }
        });
    }

    /* JADX WARN: Removed duplicated region for block: B:261:0x073b A[Catch: Exception -> 0x0777, LOOP:8: B:230:0x0663->B:261:0x073b, LOOP_END, TryCatch #2 {Exception -> 0x0777, blocks: (B:214:0x0603, B:216:0x0608, B:217:0x061c, B:219:0x0622, B:222:0x062f, B:225:0x0643, B:227:0x0650, B:229:0x065b, B:231:0x0665, B:233:0x0673, B:236:0x0690, B:238:0x0696, B:242:0x06ae, B:249:0x06c2, B:251:0x06cd, B:253:0x06e1, B:257:0x06f6, B:259:0x072b, B:258:0x0703, B:261:0x073b, B:264:0x0763), top: B:284:0x0603 }] */
    /* JADX WARN: Removed duplicated region for block: B:328:0x06c2 A[SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public /* synthetic */ void lambda$searchDialogsInternal$6$DialogsSearchAdapter(java.lang.String r38, int r39) {
        /*
            Method dump skipped, instruction units count: 1925
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.adapters.DialogsSearchAdapter.lambda$searchDialogsInternal$6$DialogsSearchAdapter(java.lang.String, int):void");
    }

    static /* synthetic */ int lambda$null$5(DialogSearchResult lhs, DialogSearchResult rhs) {
        if (lhs.date < rhs.date) {
            return 1;
        }
        if (lhs.date > rhs.date) {
            return -1;
        }
        return 0;
    }

    private void updateSearchResults(final ArrayList<TLObject> result, final ArrayList<CharSequence> names, final ArrayList<TLRPC.User> encUsers, final int searchId) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.adapters.-$$Lambda$DialogsSearchAdapter$Zc3XpXpaMvUhJvtPxr0rmTzBZBA
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$updateSearchResults$7$DialogsSearchAdapter(searchId, result, encUsers, names);
            }
        });
    }

    public /* synthetic */ void lambda$updateSearchResults$7$DialogsSearchAdapter(int searchId, ArrayList result, ArrayList encUsers, ArrayList names) {
        if (searchId != this.lastSearchId) {
            return;
        }
        this.searchWas = true;
        for (int a = 0; a < result.size(); a++) {
            TLObject obj = (TLObject) result.get(a);
            if (obj instanceof TLRPC.User) {
                TLRPC.User user = (TLRPC.User) obj;
                MessagesController.getInstance(this.currentAccount).putUser(user, true);
            } else if (obj instanceof TLRPC.Chat) {
                TLRPC.Chat chat = (TLRPC.Chat) obj;
                MessagesController.getInstance(this.currentAccount).putChat(chat, true);
            } else if (obj instanceof TLRPC.EncryptedChat) {
                TLRPC.EncryptedChat chat2 = (TLRPC.EncryptedChat) obj;
                MessagesController.getInstance(this.currentAccount).putEncryptedChat(chat2, true);
            }
        }
        int a2 = this.currentAccount;
        MessagesController.getInstance(a2).putUsers(encUsers, true);
        this.searchResult = result;
        this.searchResultNames = names;
        this.searchAdapterHelper.mergeResults(result);
        notifyDataSetChanged();
        if (this.delegate != null) {
            if (getItemCount() == 0 && (this.searchRunnable2 != null || this.searchAdapterHelper.isSearchInProgress())) {
                this.delegate.searchStateChanged(true);
            } else {
                this.delegate.searchStateChanged(false);
            }
        }
    }

    public boolean isHashtagSearch() {
        return !this.searchResultHashtags.isEmpty();
    }

    public void clearRecentHashtags() {
        this.searchAdapterHelper.clearRecentHashtags();
        this.searchResultHashtags.clear();
        notifyDataSetChanged();
    }

    public void searchDialogs(final String text) {
        final String query;
        if (text != null && text.equals(this.lastSearchText)) {
            return;
        }
        this.lastSearchText = text;
        if (this.searchRunnable != null) {
            Utilities.searchQueue.cancelRunnable(this.searchRunnable);
            this.searchRunnable = null;
        }
        Runnable runnable = this.searchRunnable2;
        if (runnable != null) {
            AndroidUtilities.cancelRunOnUIThread(runnable);
            this.searchRunnable2 = null;
        }
        if (text != null) {
            query = text.trim();
        } else {
            query = null;
        }
        if (TextUtils.isEmpty(query)) {
            this.searchAdapterHelper.unloadRecentHashtags();
            this.searchResult.clear();
            this.searchResultNames.clear();
            this.searchResultHashtags.clear();
            this.searchAdapterHelper.mergeResults(null);
            if (this.needMessagesSearch != 2) {
                this.searchAdapterHelper.queryServerSearch(null, true, true, true, true, 0, this.dialogsType == 0, 0);
            }
            this.searchWas = false;
            this.lastSearchId = -1;
            searchMessagesInternal(null);
            notifyDataSetChanged();
            return;
        }
        if (this.needMessagesSearch != 2 && query.startsWith("#") && query.length() == 1) {
            this.messagesSearchEndReached = true;
            if (this.searchAdapterHelper.loadRecentHashtags()) {
                this.searchResultMessages.clear();
                this.searchResultHashtags.clear();
                ArrayList<SearchAdapterHelper.HashtagObject> hashtags = this.searchAdapterHelper.getHashtags();
                for (int a = 0; a < hashtags.size(); a++) {
                    this.searchResultHashtags.add(hashtags.get(a).hashtag);
                }
                DialogsSearchAdapterDelegate dialogsSearchAdapterDelegate = this.delegate;
                if (dialogsSearchAdapterDelegate != null) {
                    dialogsSearchAdapterDelegate.searchStateChanged(false);
                }
            }
            notifyDataSetChanged();
        } else {
            this.searchResultHashtags.clear();
            notifyDataSetChanged();
        }
        final int searchId = this.lastSearchId + 1;
        this.lastSearchId = searchId;
        DispatchQueue dispatchQueue = Utilities.searchQueue;
        Runnable runnable2 = new Runnable() { // from class: im.uwrkaxlmjj.ui.adapters.-$$Lambda$DialogsSearchAdapter$3myNWHJIKdpYPf8ba4ITIrgcMKM
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$searchDialogs$9$DialogsSearchAdapter(query, searchId, text);
            }
        };
        this.searchRunnable = runnable2;
        dispatchQueue.postRunnable(runnable2, 300L);
    }

    public /* synthetic */ void lambda$searchDialogs$9$DialogsSearchAdapter(final String query, final int searchId, final String text) {
        this.searchRunnable = null;
        searchDialogsInternal(query, searchId);
        Runnable runnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.adapters.-$$Lambda$DialogsSearchAdapter$W-QhGnbV8nuhFTiL32eT-_6WXVg
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$8$DialogsSearchAdapter(searchId, query, text);
            }
        };
        this.searchRunnable2 = runnable;
        AndroidUtilities.runOnUIThread(runnable);
    }

    public /* synthetic */ void lambda$null$8$DialogsSearchAdapter(int searchId, String query, String text) {
        this.searchRunnable2 = null;
        if (searchId != this.lastSearchId) {
            return;
        }
        if (this.needMessagesSearch != 2) {
            this.searchAdapterHelper.queryServerSearch(query, true, this.dialogsType != 4, true, this.dialogsType != 4, 0, this.dialogsType == 0, 0);
        }
        searchMessagesInternal(text);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public int getItemCount() {
        if (isRecentSearchDisplayed()) {
            return (!this.recentSearchObjects.isEmpty() ? this.recentSearchObjects.size() + 1 : 0) + (MediaDataController.getInstance(this.currentAccount).hints.isEmpty() ? 0 : 2);
        }
        if (!this.searchResultHashtags.isEmpty()) {
            return this.searchResultHashtags.size() + 1;
        }
        int size = this.searchResult.size();
        int size2 = this.searchAdapterHelper.getLocalServerSearch().size();
        int size3 = this.searchAdapterHelper.getGlobalSearch().size();
        int size4 = this.searchAdapterHelper.getPhoneSearch().size();
        int size5 = this.searchResultMessages.size();
        int i = size + size2;
        if (size3 != 0) {
            i += size3 + 1;
        }
        if (size4 != 0) {
            i += size4;
        }
        if (size5 != 0) {
            return i + size5 + 1 + (!this.messagesSearchEndReached ? 1 : 0);
        }
        return i;
    }

    public Object getItem(int i) {
        int messagesCount;
        TLRPC.Chat chat;
        if (isRecentSearchDisplayed()) {
            messagesCount = MediaDataController.getInstance(this.currentAccount).hints.isEmpty() ? 0 : 2;
            int offset = messagesCount;
            if (i <= offset || (i - 1) - offset >= this.recentSearchObjects.size()) {
                return null;
            }
            TLObject object = this.recentSearchObjects.get((i - 1) - offset).object;
            if (object instanceof TLRPC.User) {
                TLRPC.User user = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(((TLRPC.User) object).id));
                if (user != null) {
                    return user;
                }
                return object;
            }
            if ((object instanceof TLRPC.Chat) && (chat = MessagesController.getInstance(this.currentAccount).getChat(Integer.valueOf(((TLRPC.Chat) object).id))) != null) {
                return chat;
            }
            return object;
        }
        if (!this.searchResultHashtags.isEmpty()) {
            if (i > 0) {
                return this.searchResultHashtags.get(i - 1);
            }
            return null;
        }
        ArrayList<TLObject> globalSearch = this.searchAdapterHelper.getGlobalSearch();
        ArrayList<TLObject> localServerSearch = this.searchAdapterHelper.getLocalServerSearch();
        ArrayList<Object> phoneSearch = this.searchAdapterHelper.getPhoneSearch();
        int localCount = this.searchResult.size();
        int localServerCount = localServerSearch.size();
        int phoneCount = phoneSearch.size();
        int globalCount = globalSearch.isEmpty() ? 0 : globalSearch.size() + 1;
        messagesCount = this.searchResultMessages.isEmpty() ? 0 : this.searchResultMessages.size() + 1;
        if (i >= 0 && i < localCount) {
            return this.searchResult.get(i);
        }
        int i2 = i - localCount;
        if (i2 >= 0 && i2 < localServerCount) {
            return localServerSearch.get(i2);
        }
        int i3 = i2 - localServerCount;
        if (i3 >= 0 && i3 < phoneCount) {
            return phoneSearch.get(i3);
        }
        int i4 = i3 - phoneCount;
        if (i4 > 0 && i4 < globalCount) {
            return globalSearch.get(i4 - 1);
        }
        int i5 = i4 - globalCount;
        if (i5 <= 0 || i5 >= messagesCount) {
            return null;
        }
        return this.searchResultMessages.get(i5 - 1);
    }

    public boolean isGlobalSearch(int i) {
        if (isRecentSearchDisplayed() || !this.searchResultHashtags.isEmpty()) {
            return false;
        }
        ArrayList<TLObject> globalSearch = this.searchAdapterHelper.getGlobalSearch();
        ArrayList<TLObject> localServerSearch = this.searchAdapterHelper.getLocalServerSearch();
        int localCount = this.searchResult.size();
        int localServerCount = localServerSearch.size();
        int phoneCount = this.searchAdapterHelper.getPhoneSearch().size();
        int globalCount = globalSearch.isEmpty() ? 0 : globalSearch.size() + 1;
        int messagesCount = this.searchResultMessages.isEmpty() ? 0 : this.searchResultMessages.size() + 1;
        if (i >= 0 && i < localCount) {
            return false;
        }
        int i2 = i - localCount;
        if (i2 >= 0 && i2 < localServerCount) {
            return false;
        }
        int i3 = i2 - localServerCount;
        if (i3 > 0 && i3 < phoneCount) {
            return false;
        }
        int i4 = i3 - phoneCount;
        if (i4 > 0 && i4 < globalCount) {
            return true;
        }
        int i5 = i4 - globalCount;
        return (i5 <= 0 || i5 < messagesCount) ? false : false;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public long getItemId(int i) {
        return i;
    }

    @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
    public boolean isEnabled(RecyclerView.ViewHolder holder) {
        int type = holder.getItemViewType();
        return (type == 1 || type == 3) ? false : true;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
        int i;
        View view = null;
        switch (viewType) {
            case 0:
                view = new ProfileSearchCell(this.mContext);
                view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                break;
            case 1:
                view = new GraySectionCell(this.mContext);
                break;
            case 2:
                view = new DialogCell(this.mContext, false, true);
                break;
            case 3:
                view = new LoadingCell(this.mContext);
                break;
            case 4:
                view = new HashtagSearchCell(this.mContext);
                break;
            case 5:
                RecyclerListView horizontalListView = new RecyclerListView(this.mContext) { // from class: im.uwrkaxlmjj.ui.adapters.DialogsSearchAdapter.2
                    @Override // im.uwrkaxlmjj.ui.components.RecyclerListView, androidx.recyclerview.widget.RecyclerView, android.view.ViewGroup
                    public boolean onInterceptTouchEvent(MotionEvent e) {
                        if (getParent() != null && getParent().getParent() != null) {
                            getParent().getParent().requestDisallowInterceptTouchEvent(true);
                        }
                        return super.onInterceptTouchEvent(e);
                    }
                };
                horizontalListView.setTag(9);
                horizontalListView.setItemAnimator(null);
                horizontalListView.setLayoutAnimation(null);
                LinearLayoutManager layoutManager = new LinearLayoutManager(this.mContext) { // from class: im.uwrkaxlmjj.ui.adapters.DialogsSearchAdapter.3
                    @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
                    public boolean supportsPredictiveItemAnimations() {
                        return false;
                    }
                };
                layoutManager.setOrientation(0);
                horizontalListView.setLayoutManager(layoutManager);
                horizontalListView.setAdapter(new CategoryAdapterRecycler());
                horizontalListView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.adapters.-$$Lambda$DialogsSearchAdapter$bridBufYmsJVRrg75FEH5CT4C-E
                    @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
                    public final void onItemClick(View view2, int i2) {
                        this.f$0.lambda$onCreateViewHolder$10$DialogsSearchAdapter(view2, i2);
                    }
                });
                horizontalListView.setOnItemLongClickListener(new RecyclerListView.OnItemLongClickListener() { // from class: im.uwrkaxlmjj.ui.adapters.-$$Lambda$DialogsSearchAdapter$4YGh5JMDaxV7IiGgMPJNP5sMfGM
                    @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemLongClickListener
                    public final boolean onItemClick(View view2, int i2) {
                        return this.f$0.lambda$onCreateViewHolder$11$DialogsSearchAdapter(view2, i2);
                    }
                });
                view = horizontalListView;
                this.innerListView = horizontalListView;
                break;
            case 6:
                view = new TextCell(this.mContext, 16);
                break;
        }
        if (viewType == 5) {
            view.setLayoutParams(new RecyclerView.LayoutParams(-1, AndroidUtilities.dp(86.0f)));
        } else {
            RecyclerView.LayoutParams lp = new RecyclerView.LayoutParams(-1, -2);
            if (viewType == 0 && (i = this.mProfileSearchCellMarginRight) != 0) {
                lp.rightMargin = i;
            }
            view.setLayoutParams(lp);
        }
        return new RecyclerListView.Holder(view);
    }

    public /* synthetic */ void lambda$onCreateViewHolder$10$DialogsSearchAdapter(View view1, int position) {
        DialogsSearchAdapterDelegate dialogsSearchAdapterDelegate = this.delegate;
        if (dialogsSearchAdapterDelegate != null) {
            dialogsSearchAdapterDelegate.didPressedOnSubDialog(((Integer) view1.getTag()).intValue());
        }
    }

    public /* synthetic */ boolean lambda$onCreateViewHolder$11$DialogsSearchAdapter(View view12, int position) {
        DialogsSearchAdapterDelegate dialogsSearchAdapterDelegate = this.delegate;
        if (dialogsSearchAdapterDelegate != null) {
            dialogsSearchAdapterDelegate.needRemoveHint(((Integer) view12.getTag()).intValue());
            return true;
        }
        return true;
    }

    /* JADX WARN: Removed duplicated region for block: B:145:0x03af A[PHI: r10
      0x03af: PHI (r10v2 'name' java.lang.CharSequence) = 
      (r10v0 'name' java.lang.CharSequence)
      (r10v0 'name' java.lang.CharSequence)
      (r10v4 'name' java.lang.CharSequence)
      (r10v4 'name' java.lang.CharSequence)
      (r10v4 'name' java.lang.CharSequence)
      (r10v4 'name' java.lang.CharSequence)
      (r10v4 'name' java.lang.CharSequence)
     binds: [B:144:0x03ad, B:129:0x0364, B:104:0x02d2, B:105:0x02d4, B:107:0x02d8, B:109:0x02e0, B:111:0x02fb] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:170:0x0416  */
    /* JADX WARN: Removed duplicated region for block: B:171:0x0418  */
    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void onBindViewHolder(androidx.recyclerview.widget.RecyclerView.ViewHolder r29, int r30) {
        /*
            Method dump skipped, instruction units count: 1066
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.adapters.DialogsSearchAdapter.onBindViewHolder(androidx.recyclerview.widget.RecyclerView$ViewHolder, int):void");
    }

    public /* synthetic */ void lambda$onBindViewHolder$12$DialogsSearchAdapter(View v) {
        DialogsSearchAdapterDelegate dialogsSearchAdapterDelegate = this.delegate;
        if (dialogsSearchAdapterDelegate != null) {
            dialogsSearchAdapterDelegate.needClearList();
        }
    }

    public /* synthetic */ void lambda$onBindViewHolder$13$DialogsSearchAdapter(View v) {
        DialogsSearchAdapterDelegate dialogsSearchAdapterDelegate = this.delegate;
        if (dialogsSearchAdapterDelegate != null) {
            dialogsSearchAdapterDelegate.needClearList();
        }
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public int getItemViewType(int i) {
        if (isRecentSearchDisplayed()) {
            int offset = MediaDataController.getInstance(this.currentAccount).hints.isEmpty() ? 0 : 2;
            if (i <= offset) {
                return (i == offset || i % 2 == 0) ? 1 : 5;
            }
            return 0;
        }
        if (!this.searchResultHashtags.isEmpty()) {
            return i == 0 ? 1 : 4;
        }
        ArrayList<TLObject> globalSearch = this.searchAdapterHelper.getGlobalSearch();
        int localCount = this.searchResult.size();
        int localServerCount = this.searchAdapterHelper.getLocalServerSearch().size();
        int phoneCount = this.searchAdapterHelper.getPhoneSearch().size();
        int globalCount = globalSearch.isEmpty() ? 0 : globalSearch.size() + 1;
        int messagesCount = this.searchResultMessages.isEmpty() ? 0 : this.searchResultMessages.size() + 1;
        if (i >= 0 && i < localCount) {
            return 0;
        }
        int i2 = i - localCount;
        if (i2 >= 0 && i2 < localServerCount) {
            return 0;
        }
        int i3 = i2 - localServerCount;
        if (i3 >= 0 && i3 < phoneCount) {
            Object object = getItem(i3);
            if (!(object instanceof String)) {
                return 0;
            }
            String str = (String) object;
            return "section".equals(str) ? 1 : 6;
        }
        int i4 = i3 - phoneCount;
        if (i4 >= 0 && i4 < globalCount) {
            return i4 == 0 ? 1 : 0;
        }
        int i5 = i4 - globalCount;
        if (i5 < 0 || i5 >= messagesCount) {
            return 3;
        }
        return i5 == 0 ? 1 : 2;
    }
}
