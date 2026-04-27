package im.uwrkaxlmjj.ui.adapters;

import android.util.SparseArray;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ContactsController;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.MessagesStorage;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.phoneformat.PhoneFormat;
import im.uwrkaxlmjj.sqlite.SQLiteCursor;
import im.uwrkaxlmjj.sqlite.SQLitePreparedStatement;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.adapters.SearchAdapterHelper;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.slf4j.Marker;

/* JADX INFO: loaded from: classes5.dex */
public class SearchAdapterHelper {
    private boolean allResultsAreGlobal;
    private int channelLastReqId;
    private SearchAdapterHelperDelegate delegate;
    private ArrayList<HashtagObject> hashtags;
    private HashMap<String, HashtagObject> hashtagsByText;
    private String lastFoundChannel;
    private int lastReqId;
    private ArrayList<TLObject> localSearchResults;
    private int reqId = 0;
    private String lastFoundUsername = null;
    private ArrayList<TLObject> localServerSearch = new ArrayList<>();
    private ArrayList<TLObject> globalSearch = new ArrayList<>();
    private SparseArray<TLObject> globalSearchMap = new SparseArray<>();
    private ArrayList<TLObject> groupSearch = new ArrayList<>();
    private SparseArray<TLObject> groupSearchMap = new SparseArray<>();
    private SparseArray<TLObject> phoneSearchMap = new SparseArray<>();
    private ArrayList<Object> phonesSearch = new ArrayList<>();
    private int currentAccount = UserConfig.selectedAccount;
    private int channelReqId = 0;
    private boolean hashtagsLoadedFromDb = false;

    public static class HashtagObject {
        int date;
        String hashtag;
    }

    public interface SearchAdapterHelperDelegate {
        SparseArray<TLRPC.User> getExcludeUsers();

        void onDataSetChanged();

        void onSetHashtags(ArrayList<HashtagObject> arrayList, HashMap<String, HashtagObject> map);

        /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.adapters.SearchAdapterHelper$SearchAdapterHelperDelegate$-CC, reason: invalid class name */
        public final /* synthetic */ class CC {
            public static void $default$onSetHashtags(SearchAdapterHelperDelegate _this, ArrayList arrayList, HashMap map) {
            }

            public static SparseArray $default$getExcludeUsers(SearchAdapterHelperDelegate _this) {
                return null;
            }
        }
    }

    protected static final class DialogSearchResult {
        public int date;
        public CharSequence name;
        public TLObject object;

        protected DialogSearchResult() {
        }
    }

    public SearchAdapterHelper(boolean global) {
        this.allResultsAreGlobal = global;
    }

    public boolean isSearchInProgress() {
        return (this.reqId == 0 && this.channelReqId == 0) ? false : true;
    }

    public void queryServerSearch(final String query, boolean allowUsername, final boolean allowChats, final boolean allowBots, final boolean allowSelf, int channelId, boolean phoneNumbers, int type) {
        if (this.reqId != 0) {
            ConnectionsManager.getInstance(this.currentAccount).cancelRequest(this.reqId, true);
            this.reqId = 0;
        }
        if (this.channelReqId != 0) {
            ConnectionsManager.getInstance(this.currentAccount).cancelRequest(this.channelReqId, true);
            this.channelReqId = 0;
        }
        if (query == null) {
            this.groupSearch.clear();
            this.groupSearchMap.clear();
            this.globalSearch.clear();
            this.globalSearchMap.clear();
            this.localServerSearch.clear();
            this.phonesSearch.clear();
            this.phoneSearchMap.clear();
            this.lastReqId = 0;
            this.channelLastReqId = 0;
            this.delegate.onDataSetChanged();
            return;
        }
        if (query.length() <= 0) {
            this.groupSearch.clear();
            this.groupSearchMap.clear();
            this.channelLastReqId = 0;
            this.delegate.onDataSetChanged();
        } else if (channelId == 0) {
            this.lastFoundChannel = query.toLowerCase();
        } else {
            TLRPC.TL_channels_getParticipants req = new TLRPC.TL_channels_getParticipants();
            if (type == 1) {
                req.filter = new TLRPC.TL_channelParticipantsAdmins();
            } else if (type == 3) {
                req.filter = new TLRPC.TL_channelParticipantsBanned();
            } else if (type == 0) {
                req.filter = new TLRPC.TL_channelParticipantsKicked();
            } else {
                req.filter = new TLRPC.TL_channelParticipantsSearch();
            }
            req.filter.q = query;
            req.limit = 50;
            req.offset = 0;
            req.channel = MessagesController.getInstance(this.currentAccount).getInputChannel(channelId);
            final int currentReqId = this.channelLastReqId + 1;
            this.channelLastReqId = currentReqId;
            this.channelReqId = ConnectionsManager.getInstance(this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.adapters.-$$Lambda$SearchAdapterHelper$hTV0NSRLBCLp1PMJCYsONwJMb3Q
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$queryServerSearch$1$SearchAdapterHelper(currentReqId, query, allowSelf, tLObject, tL_error);
                }
            }, 2);
        }
        if (allowUsername) {
            if (query.length() > 0) {
                TLRPC.TL_contacts_search req2 = new TLRPC.TL_contacts_search();
                req2.q = query;
                req2.limit = 50;
                final int currentReqId2 = this.lastReqId + 1;
                this.lastReqId = currentReqId2;
                this.reqId = ConnectionsManager.getInstance(this.currentAccount).sendRequest(req2, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.adapters.-$$Lambda$SearchAdapterHelper$Ec9VgZg0lAJ7-WgfYVWgxKe6lns
                    @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                    public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                        this.f$0.lambda$queryServerSearch$3$SearchAdapterHelper(currentReqId2, allowChats, allowBots, allowSelf, query, tLObject, tL_error);
                    }
                }, 2);
            } else {
                this.globalSearch.clear();
                this.globalSearchMap.clear();
                this.localServerSearch.clear();
                this.lastReqId = 0;
                this.delegate.onDataSetChanged();
            }
        }
        if (phoneNumbers && query.startsWith(Marker.ANY_NON_NULL_MARKER) && query.length() > 3) {
            this.phonesSearch.clear();
            this.phoneSearchMap.clear();
            String phone = PhoneFormat.stripExceptNumbers(query);
            ArrayList<TLRPC.Contact> arrayList = ContactsController.getInstance(this.currentAccount).contacts;
            boolean hasFullMatch = false;
            int N = arrayList.size();
            for (int a = 0; a < N; a++) {
                TLRPC.Contact contact = arrayList.get(a);
                TLRPC.User user = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(contact.user_id));
                if (user != null && user.phone != null && user.phone.startsWith(phone)) {
                    if (!hasFullMatch) {
                        hasFullMatch = user.phone.length() == phone.length();
                    }
                    this.phonesSearch.add(user);
                    this.phoneSearchMap.put(user.id, user);
                }
            }
            if (!hasFullMatch) {
                this.phonesSearch.add("section");
                this.phonesSearch.add(phone);
            }
            this.delegate.onDataSetChanged();
        }
    }

    public /* synthetic */ void lambda$queryServerSearch$1$SearchAdapterHelper(final int currentReqId, final String query, final boolean allowSelf, final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.adapters.-$$Lambda$SearchAdapterHelper$Ue2bdAvCUvHG0gFYGju7cdG6_oc
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$0$SearchAdapterHelper(currentReqId, error, response, query, allowSelf);
            }
        });
    }

    public /* synthetic */ void lambda$null$0$SearchAdapterHelper(int currentReqId, TLRPC.TL_error error, TLObject response, String query, boolean allowSelf) {
        if (currentReqId == this.channelLastReqId && error == null) {
            TLRPC.TL_channels_channelParticipants res = (TLRPC.TL_channels_channelParticipants) response;
            this.lastFoundChannel = query.toLowerCase();
            MessagesController.getInstance(this.currentAccount).putUsers(res.users, false);
            this.groupSearch.clear();
            this.groupSearchMap.clear();
            this.groupSearch.addAll(res.participants);
            int currentUserId = UserConfig.getInstance(this.currentAccount).getClientUserId();
            int N = res.participants.size();
            for (int a = 0; a < N; a++) {
                TLRPC.ChannelParticipant participant = res.participants.get(a);
                if (!allowSelf && participant.user_id == currentUserId) {
                    this.groupSearch.remove(participant);
                } else {
                    this.groupSearchMap.put(participant.user_id, participant);
                }
            }
            ArrayList<TLObject> arrayList = this.localSearchResults;
            if (arrayList != null) {
                mergeResults(arrayList);
            }
            this.delegate.onDataSetChanged();
        }
        this.channelReqId = 0;
    }

    public /* synthetic */ void lambda$queryServerSearch$3$SearchAdapterHelper(final int currentReqId, final boolean allowChats, final boolean allowBots, final boolean allowSelf, final String query, final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.adapters.-$$Lambda$SearchAdapterHelper$7MPLLuYP-cFkvuNsVn6IRARhrGY
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$2$SearchAdapterHelper(currentReqId, error, response, allowChats, allowBots, allowSelf, query);
            }
        });
    }

    public /* synthetic */ void lambda$null$2$SearchAdapterHelper(int currentReqId, TLRPC.TL_error error, TLObject response, boolean allowChats, boolean allowBots, boolean allowSelf, String query) {
        ArrayList<TLRPC.Peer> arrayList;
        if (currentReqId == this.lastReqId) {
            this.reqId = 0;
            if (error == null) {
                TLRPC.TL_contacts_found res = (TLRPC.TL_contacts_found) response;
                this.globalSearch.clear();
                this.globalSearchMap.clear();
                this.localServerSearch.clear();
                MessagesController.getInstance(this.currentAccount).putChats(res.chats, false);
                MessagesController.getInstance(this.currentAccount).putUsers(res.users, false);
                MessagesStorage.getInstance(this.currentAccount).putUsersAndChats(res.users, res.chats, true, true);
                SparseArray<TLRPC.Chat> chatsMap = new SparseArray<>();
                SparseArray<TLRPC.User> usersMap = new SparseArray<>();
                for (int a = 0; a < res.chats.size(); a++) {
                    TLRPC.Chat chat = res.chats.get(a);
                    chatsMap.put(chat.id, chat);
                }
                for (int a2 = 0; a2 < res.users.size(); a2++) {
                    TLRPC.User user = res.users.get(a2);
                    usersMap.put(user.id, user);
                }
                for (int b = 0; b < 2; b++) {
                    if (b == 0) {
                        if (this.allResultsAreGlobal) {
                            arrayList = res.my_results;
                        }
                    } else {
                        arrayList = res.results;
                    }
                    for (int a3 = 0; a3 < arrayList.size(); a3++) {
                        TLRPC.Peer peer = arrayList.get(a3);
                        TLRPC.User user2 = null;
                        TLRPC.Chat chat2 = null;
                        if (peer.user_id != 0) {
                            user2 = usersMap.get(peer.user_id);
                        } else if (peer.chat_id != 0) {
                            chat2 = chatsMap.get(peer.chat_id);
                        } else if (peer.channel_id != 0) {
                            chat2 = chatsMap.get(peer.channel_id);
                        }
                        if (chat2 != null) {
                            if (allowChats) {
                                this.globalSearch.add(chat2);
                                this.globalSearchMap.put(-chat2.id, chat2);
                            }
                        } else if (user2 != null && ((allowBots || !user2.bot) && (allowSelf || !user2.self))) {
                            this.globalSearch.add(user2);
                            this.globalSearchMap.put(user2.id, user2);
                        }
                    }
                }
                if (!this.allResultsAreGlobal) {
                    for (int a4 = 0; a4 < res.my_results.size(); a4++) {
                        TLRPC.Peer peer2 = res.my_results.get(a4);
                        TLRPC.User user3 = null;
                        TLRPC.Chat chat3 = null;
                        if (peer2.user_id != 0) {
                            user3 = usersMap.get(peer2.user_id);
                        } else if (peer2.chat_id != 0) {
                            chat3 = chatsMap.get(peer2.chat_id);
                        } else if (peer2.channel_id != 0) {
                            chat3 = chatsMap.get(peer2.channel_id);
                        }
                        if (chat3 != null) {
                            if (allowChats) {
                                this.localServerSearch.add(chat3);
                                this.globalSearchMap.put(-chat3.id, chat3);
                            }
                        } else if (user3 != null) {
                            this.localServerSearch.add(user3);
                            this.globalSearchMap.put(user3.id, user3);
                        }
                    }
                }
                this.lastFoundUsername = query.toLowerCase();
                ArrayList<TLObject> arrayList2 = this.localSearchResults;
                if (arrayList2 != null) {
                    mergeResults(arrayList2);
                }
                mergeExcludeResults();
                this.delegate.onDataSetChanged();
            }
        }
    }

    public void unloadRecentHashtags() {
        this.hashtagsLoadedFromDb = false;
    }

    public boolean loadRecentHashtags() {
        if (this.hashtagsLoadedFromDb) {
            return true;
        }
        MessagesStorage.getInstance(this.currentAccount).getStorageQueue().postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.adapters.-$$Lambda$SearchAdapterHelper$MjffmeCzPxc8Do8U5s0nYST3zyY
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$loadRecentHashtags$6$SearchAdapterHelper();
            }
        });
        return false;
    }

    public /* synthetic */ void lambda$loadRecentHashtags$6$SearchAdapterHelper() {
        try {
            SQLiteCursor cursor = MessagesStorage.getInstance(this.currentAccount).getDatabase().queryFinalized("SELECT id, date FROM hashtag_recent_v2 WHERE 1", new Object[0]);
            final ArrayList<HashtagObject> arrayList = new ArrayList<>();
            final HashMap<String, HashtagObject> hashMap = new HashMap<>();
            while (cursor.next()) {
                HashtagObject hashtagObject = new HashtagObject();
                hashtagObject.hashtag = cursor.stringValue(0);
                hashtagObject.date = cursor.intValue(1);
                arrayList.add(hashtagObject);
                hashMap.put(hashtagObject.hashtag, hashtagObject);
            }
            cursor.dispose();
            Collections.sort(arrayList, new Comparator() { // from class: im.uwrkaxlmjj.ui.adapters.-$$Lambda$SearchAdapterHelper$jCJuwSqnZlR4QJdJqIoAp7K1Nl4
                @Override // java.util.Comparator
                public final int compare(Object obj, Object obj2) {
                    return SearchAdapterHelper.lambda$null$4((SearchAdapterHelper.HashtagObject) obj, (SearchAdapterHelper.HashtagObject) obj2);
                }
            });
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.adapters.-$$Lambda$SearchAdapterHelper$1l0LSVMpBLMFKND2hClwZorjNsg
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$5$SearchAdapterHelper(arrayList, hashMap);
                }
            });
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    static /* synthetic */ int lambda$null$4(HashtagObject lhs, HashtagObject rhs) {
        if (lhs.date < rhs.date) {
            return 1;
        }
        if (lhs.date > rhs.date) {
            return -1;
        }
        return 0;
    }

    public void mergeResults(ArrayList<TLObject> localResults) {
        this.localSearchResults = localResults;
        if (this.globalSearchMap.size() == 0 || localResults == null) {
            return;
        }
        int count = localResults.size();
        for (int a = 0; a < count; a++) {
            TLObject obj = localResults.get(a);
            if (obj instanceof TLRPC.User) {
                TLRPC.User user = (TLRPC.User) obj;
                TLRPC.User u = (TLRPC.User) this.globalSearchMap.get(user.id);
                if (u != null) {
                    this.globalSearch.remove(u);
                    this.localServerSearch.remove(u);
                    this.globalSearchMap.remove(u.id);
                }
                TLObject participant = this.groupSearchMap.get(user.id);
                if (participant != null) {
                    this.groupSearch.remove(participant);
                    this.groupSearchMap.remove(user.id);
                }
                Object object = this.phoneSearchMap.get(user.id);
                if (object != null) {
                    this.phonesSearch.remove(object);
                    this.phoneSearchMap.remove(user.id);
                }
            } else if (obj instanceof TLRPC.Chat) {
                TLRPC.Chat chat = (TLRPC.Chat) obj;
                TLRPC.Chat c = (TLRPC.Chat) this.globalSearchMap.get(-chat.id);
                if (c != null) {
                    this.globalSearch.remove(c);
                    this.localServerSearch.remove(c);
                    this.globalSearchMap.remove(-c.id);
                }
            }
        }
    }

    public void mergeExcludeResults() {
        SparseArray<TLRPC.User> ignoreUsers;
        SearchAdapterHelperDelegate searchAdapterHelperDelegate = this.delegate;
        if (searchAdapterHelperDelegate == null || (ignoreUsers = searchAdapterHelperDelegate.getExcludeUsers()) == null) {
            return;
        }
        int size = ignoreUsers.size();
        for (int a = 0; a < size; a++) {
            TLRPC.User u = (TLRPC.User) this.globalSearchMap.get(ignoreUsers.keyAt(a));
            if (u != null) {
                this.globalSearch.remove(u);
                this.localServerSearch.remove(u);
                this.globalSearchMap.remove(u.id);
            }
        }
    }

    public void setDelegate(SearchAdapterHelperDelegate searchAdapterHelperDelegate) {
        this.delegate = searchAdapterHelperDelegate;
    }

    public void addHashtagsFromMessage(CharSequence message) {
        if (message == null) {
            return;
        }
        boolean changed = false;
        Pattern pattern = Pattern.compile("(^|\\s)#[\\w@.]+");
        Matcher matcher = pattern.matcher(message);
        while (matcher.find()) {
            int start = matcher.start();
            int end = matcher.end();
            if (message.charAt(start) != '@' && message.charAt(start) != '#') {
                start++;
            }
            String hashtag = message.subSequence(start, end).toString();
            if (this.hashtagsByText == null) {
                this.hashtagsByText = new HashMap<>();
                this.hashtags = new ArrayList<>();
            }
            HashtagObject hashtagObject = this.hashtagsByText.get(hashtag);
            if (hashtagObject == null) {
                hashtagObject = new HashtagObject();
                hashtagObject.hashtag = hashtag;
                this.hashtagsByText.put(hashtagObject.hashtag, hashtagObject);
            } else {
                this.hashtags.remove(hashtagObject);
            }
            hashtagObject.date = (int) (System.currentTimeMillis() / 1000);
            this.hashtags.add(0, hashtagObject);
            changed = true;
        }
        if (changed) {
            putRecentHashtags(this.hashtags);
        }
    }

    private void putRecentHashtags(final ArrayList<HashtagObject> arrayList) {
        MessagesStorage.getInstance(this.currentAccount).getStorageQueue().postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.adapters.-$$Lambda$SearchAdapterHelper$n795JVZHSvh5KlQ4118VhyaxJmI
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$putRecentHashtags$7$SearchAdapterHelper(arrayList);
            }
        });
    }

    public /* synthetic */ void lambda$putRecentHashtags$7$SearchAdapterHelper(ArrayList arrayList) {
        SQLitePreparedStatement state = null;
        try {
            try {
                MessagesStorage.getInstance(this.currentAccount).getDatabase().beginTransaction();
            } catch (Exception e) {
                try {
                    FileLog.e("putRecentHashtags ---> exception 1 ", e);
                } catch (Exception e2) {
                    FileLog.e("putRecentHashtags ---> exception 3 ", e2);
                    if (state == null) {
                        return;
                    }
                }
            }
            SQLitePreparedStatement state2 = MessagesStorage.getInstance(this.currentAccount).getDatabase().executeFast("REPLACE INTO hashtag_recent_v2 VALUES(?, ?)");
            for (int a = 0; a < arrayList.size() && a != 100; a++) {
                HashtagObject hashtagObject = (HashtagObject) arrayList.get(a);
                state2.requery();
                state2.bindString(1, hashtagObject.hashtag);
                state2.bindInteger(2, hashtagObject.date);
                state2.step();
            }
            state2.dispose();
            state = null;
            MessagesStorage.getInstance(this.currentAccount).getDatabase().commitTransaction();
            if (arrayList.size() >= 100) {
                try {
                    MessagesStorage.getInstance(this.currentAccount).getDatabase().beginTransaction();
                } catch (Exception e3) {
                    FileLog.e("putRecentHashtags ---> exception 2 ", e3);
                }
                for (int a2 = 100; a2 < arrayList.size(); a2++) {
                    MessagesStorage.getInstance(this.currentAccount).getDatabase().executeFast("DELETE FROM hashtag_recent_v2 WHERE id = '" + ((HashtagObject) arrayList.get(a2)).hashtag + "'").stepThis().dispose();
                }
                int a3 = this.currentAccount;
                MessagesStorage.getInstance(a3).getDatabase().commitTransaction();
            }
            if (0 == 0) {
                return;
            }
            state.dispose();
        } catch (Throwable th) {
            if (state != null) {
                state.dispose();
            }
            throw th;
        }
    }

    public ArrayList<TLObject> getGlobalSearch() {
        return this.globalSearch;
    }

    public ArrayList<Object> getPhoneSearch() {
        return this.phonesSearch;
    }

    public ArrayList<TLObject> getLocalServerSearch() {
        return this.localServerSearch;
    }

    public ArrayList<TLObject> getGroupSearch() {
        return this.groupSearch;
    }

    public ArrayList<HashtagObject> getHashtags() {
        return this.hashtags;
    }

    public String getLastFoundUsername() {
        return this.lastFoundUsername;
    }

    public String getLastFoundChannel() {
        return this.lastFoundChannel;
    }

    public void clearRecentHashtags() {
        this.hashtags = new ArrayList<>();
        this.hashtagsByText = new HashMap<>();
        MessagesStorage.getInstance(this.currentAccount).getStorageQueue().postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.adapters.-$$Lambda$SearchAdapterHelper$QpjcQvtnqk75BGe4X0lANBjcCvk
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$clearRecentHashtags$8$SearchAdapterHelper();
            }
        });
    }

    public /* synthetic */ void lambda$clearRecentHashtags$8$SearchAdapterHelper() {
        try {
            MessagesStorage.getInstance(this.currentAccount).getDatabase().executeFast("DELETE FROM hashtag_recent_v2 WHERE 1").stepThis().dispose();
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    /* JADX INFO: renamed from: setHashtags, reason: merged with bridge method [inline-methods] */
    public void lambda$null$5$SearchAdapterHelper(ArrayList<HashtagObject> arrayList, HashMap<String, HashtagObject> hashMap) {
        this.hashtags = arrayList;
        this.hashtagsByText = hashMap;
        this.hashtagsLoadedFromDb = true;
        this.delegate.onSetHashtags(arrayList, hashMap);
    }
}
