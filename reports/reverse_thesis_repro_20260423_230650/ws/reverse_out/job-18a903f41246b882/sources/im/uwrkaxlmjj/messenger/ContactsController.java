package im.uwrkaxlmjj.messenger;

import android.accounts.Account;
import android.accounts.AccountManager;
import android.content.ContentProviderOperation;
import android.content.ContentProviderResult;
import android.content.ContentResolver;
import android.content.ContentValues;
import android.content.SharedPreferences;
import android.database.ContentObserver;
import android.database.Cursor;
import android.net.Uri;
import android.os.Build;
import android.provider.ContactsContract;
import android.text.TextUtils;
import android.util.SparseArray;
import androidx.exifinterface.media.ExifInterface;
import com.bjz.comm.net.premission.PermissionUtils;
import im.uwrkaxlmjj.messenger.ContactsController;
import im.uwrkaxlmjj.messenger.support.SparseLongArray;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.tgnet.TLRPCContacts;
import im.uwrkaxlmjj.ui.hui.CharacterParser;
import im.uwrkaxlmjj.ui.hviews.swipelist.SlidingItemMenuRecyclerView;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Marker;
import org.webrtc.mozi.ScreenAudioCapturer;

/* JADX INFO: loaded from: classes2.dex */
public class ContactsController extends BaseController {
    private static volatile ContactsController[] Instance = new ContactsController[3];
    public static final int PRIVACY_RULES_TYPE_ADDED_BY_PHONE = 7;
    public static final int PRIVACY_RULES_TYPE_CALLS = 2;
    public static final int PRIVACY_RULES_TYPE_COUNT = 9;
    public static final int PRIVACY_RULES_TYPE_FORWARDS = 5;
    public static final int PRIVACY_RULES_TYPE_INVITE = 1;
    public static final int PRIVACY_RULES_TYPE_LASTSEEN = 0;
    public static final int PRIVACY_RULES_TYPE_MOMENT = 8;
    public static final int PRIVACY_RULES_TYPE_P2P = 3;
    public static final int PRIVACY_RULES_TYPE_PHONE = 6;
    public static final int PRIVACY_RULES_TYPE_PHOTO = 4;
    private ArrayList<TLRPC.PrivacyRule> addedByPhonePrivacyRules;
    private ArrayList<TLRPC.PrivacyRule> callPrivacyRules;
    private int completedRequestsCount;
    public ArrayList<TLRPC.Contact> contacts;
    public HashMap<String, Contact> contactsBook;
    private boolean contactsBookLoaded;
    public HashMap<String, Contact> contactsBookSPhones;
    public HashMap<String, TLRPC.Contact> contactsByPhone;
    public HashMap<String, TLRPC.Contact> contactsByShortPhone;
    public ConcurrentHashMap<Integer, TLRPC.Contact> contactsDict;
    public boolean contactsLoaded;
    private boolean contactsSyncInProgress;
    private ArrayList<Integer> delayedContactsUpdate;
    private int deleteAccountTTL;
    private ArrayList<TLRPC.PrivacyRule> forwardsPrivacyRules;
    private ArrayList<TLRPC.PrivacyRule> groupPrivacyRules;
    private boolean ignoreChanges;
    private String inviteLink;
    private String lastContactsVersions;
    private ArrayList<TLRPC.PrivacyRule> lastseenPrivacyRules;
    private final Object loadContactsSync;
    private boolean loadingContacts;
    private int loadingDeleteInfo;
    private int[] loadingPrivacyInfo;
    private boolean migratingContacts;
    private ArrayList<TLRPC.PrivacyRule> momentPrivacyRules;
    private final Object observerLock;
    private ArrayList<TLRPC.PrivacyRule> p2pPrivacyRules;
    public ArrayList<Contact> phoneBookContacts;
    public ArrayList<String> phoneBookSectionsArray;
    public HashMap<String, ArrayList<Object>> phoneBookSectionsDict;
    private ArrayList<TLRPC.PrivacyRule> phonePrivacyRules;
    private ArrayList<TLRPC.PrivacyRule> profilePhotoPrivacyRules;
    private String[] projectionNames;
    private String[] projectionPhones;
    private HashMap<String, String> sectionsToReplace;
    public ArrayList<String> sortedUsersMutualSectionsArray;
    public ArrayList<String> sortedUsersSectionsArray;
    private Account systemAccount;
    private boolean updatingInviteLink;
    public HashMap<String, ArrayList<TLRPC.Contact>> usersMutualSectionsDict;
    public HashMap<String, ArrayList<TLRPC.Contact>> usersSectionsDict;

    /* JADX INFO: Access modifiers changed from: private */
    class MyContentObserver extends ContentObserver {
        private Runnable checkRunnable;

        static /* synthetic */ void lambda$new$0() {
            for (int a = 0; a < 3; a++) {
                if (UserConfig.getInstance(a).isClientActivated()) {
                    ConnectionsManager.getInstance(a).resumeNetworkMaybe();
                }
            }
        }

        public MyContentObserver() {
            super(null);
            this.checkRunnable = new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ContactsController$MyContentObserver$jd3vvBUi1bIxMGi6UvPUtrMMWBk
                @Override // java.lang.Runnable
                public final void run() {
                    ContactsController.MyContentObserver.lambda$new$0();
                }
            };
        }

        @Override // android.database.ContentObserver
        public void onChange(boolean selfChange) {
            super.onChange(selfChange);
            synchronized (ContactsController.this.observerLock) {
                if (ContactsController.this.ignoreChanges) {
                    return;
                }
                Utilities.globalQueue.cancelRunnable(this.checkRunnable);
                Utilities.globalQueue.postRunnable(this.checkRunnable, 500L);
            }
        }

        @Override // android.database.ContentObserver
        public boolean deliverSelfNotifications() {
            return false;
        }
    }

    public static class Contact {
        public int contact_id;
        public String first_name;
        public int imported;
        public boolean isGoodProvider;
        public String key;
        public String last_name;
        public boolean namesFilled;
        public String provider;
        public TLRPC.User user;
        public ArrayList<String> phones = new ArrayList<>(4);
        public ArrayList<String> phoneTypes = new ArrayList<>(4);
        public ArrayList<String> shortPhones = new ArrayList<>(4);
        public ArrayList<Integer> phoneDeleted = new ArrayList<>(4);

        public String getLetter() {
            return getLetter(this.first_name, this.last_name);
        }

        public static String getLetter(String first_name, String last_name) {
            if (!TextUtils.isEmpty(first_name)) {
                return first_name.substring(0, 1);
            }
            if (!TextUtils.isEmpty(last_name)) {
                return last_name.substring(0, 1);
            }
            return "#";
        }
    }

    public static ContactsController getInstance(int num) {
        ContactsController localInstance = Instance[num];
        if (localInstance == null) {
            synchronized (ContactsController.class) {
                localInstance = Instance[num];
                if (localInstance == null) {
                    ContactsController[] contactsControllerArr = Instance;
                    ContactsController contactsController = new ContactsController(num);
                    localInstance = contactsController;
                    contactsControllerArr[num] = contactsController;
                }
            }
        }
        return localInstance;
    }

    public ContactsController(int instance) {
        super(instance);
        this.loadContactsSync = new Object();
        this.observerLock = new Object();
        this.lastContactsVersions = "";
        this.delayedContactsUpdate = new ArrayList<>();
        this.sectionsToReplace = new HashMap<>();
        this.loadingPrivacyInfo = new int[9];
        this.projectionPhones = new String[]{"lookup", "data1", "data2", "data3", "display_name", "account_type"};
        this.projectionNames = new String[]{"lookup", "data2", "data3", "data5"};
        this.contactsBook = new HashMap<>();
        this.contactsBookSPhones = new HashMap<>();
        this.phoneBookContacts = new ArrayList<>();
        this.phoneBookSectionsDict = new HashMap<>();
        this.phoneBookSectionsArray = new ArrayList<>();
        this.contacts = new ArrayList<>();
        this.contactsDict = new ConcurrentHashMap<>(20, 1.0f, 2);
        this.usersSectionsDict = new HashMap<>();
        this.sortedUsersSectionsArray = new ArrayList<>();
        this.usersMutualSectionsDict = new HashMap<>();
        this.sortedUsersMutualSectionsArray = new ArrayList<>();
        this.contactsByPhone = new HashMap<>();
        this.contactsByShortPhone = new HashMap<>();
        SharedPreferences preferences = MessagesController.getMainSettings(this.currentAccount);
        if (preferences.getBoolean("needGetStatuses", false)) {
            reloadContactsStatuses();
        }
        this.sectionsToReplace.put("À", ExifInterface.GPS_MEASUREMENT_IN_PROGRESS);
        this.sectionsToReplace.put("Á", ExifInterface.GPS_MEASUREMENT_IN_PROGRESS);
        this.sectionsToReplace.put("Ä", ExifInterface.GPS_MEASUREMENT_IN_PROGRESS);
        this.sectionsToReplace.put("Ù", "U");
        this.sectionsToReplace.put("Ú", "U");
        this.sectionsToReplace.put("Ü", "U");
        this.sectionsToReplace.put("Ì", "I");
        this.sectionsToReplace.put("Í", "I");
        this.sectionsToReplace.put("Ï", "I");
        this.sectionsToReplace.put("È", ExifInterface.LONGITUDE_EAST);
        this.sectionsToReplace.put("É", ExifInterface.LONGITUDE_EAST);
        this.sectionsToReplace.put("Ê", ExifInterface.LONGITUDE_EAST);
        this.sectionsToReplace.put("Ë", ExifInterface.LONGITUDE_EAST);
        this.sectionsToReplace.put("Ò", "O");
        this.sectionsToReplace.put("Ó", "O");
        this.sectionsToReplace.put("Ö", "O");
        this.sectionsToReplace.put("Ç", "C");
        this.sectionsToReplace.put("Ñ", "N");
        this.sectionsToReplace.put("Ÿ", "Y");
        this.sectionsToReplace.put("Ý", "Y");
        this.sectionsToReplace.put("Ţ", "Y");
        if (instance == 0) {
            Utilities.globalQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ContactsController$CkePsnGtVlx7cj0t4H51MlZFOJU
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$0$ContactsController();
                }
            });
        }
    }

    public /* synthetic */ void lambda$new$0$ContactsController() {
        try {
            if (hasContactsPermission()) {
                ApplicationLoader.applicationContext.getContentResolver().registerContentObserver(ContactsContract.Contacts.CONTENT_URI, true, new MyContentObserver());
            }
        } catch (Throwable th) {
        }
    }

    public void cleanup() {
        this.contactsBook.clear();
        this.contactsBookSPhones.clear();
        this.phoneBookContacts.clear();
        this.contacts.clear();
        this.contactsDict.clear();
        this.usersSectionsDict.clear();
        this.usersMutualSectionsDict.clear();
        this.sortedUsersSectionsArray.clear();
        this.sortedUsersMutualSectionsArray.clear();
        this.delayedContactsUpdate.clear();
        this.contactsByPhone.clear();
        this.contactsByShortPhone.clear();
        this.phoneBookSectionsDict.clear();
        this.phoneBookSectionsArray.clear();
        this.loadingContacts = false;
        this.contactsSyncInProgress = false;
        this.contactsLoaded = false;
        this.contactsBookLoaded = false;
        this.lastContactsVersions = "";
        this.loadingDeleteInfo = 0;
        this.deleteAccountTTL = 0;
        int a = 0;
        while (true) {
            int[] iArr = this.loadingPrivacyInfo;
            if (a < iArr.length) {
                iArr[a] = 0;
                a++;
            } else {
                this.lastseenPrivacyRules = null;
                this.groupPrivacyRules = null;
                this.callPrivacyRules = null;
                this.p2pPrivacyRules = null;
                this.profilePhotoPrivacyRules = null;
                this.forwardsPrivacyRules = null;
                this.phonePrivacyRules = null;
                Utilities.globalQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ContactsController$-6gvPctX8D9VFFU-Klq2mPsgKuk
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$cleanup$1$ContactsController();
                    }
                });
                return;
            }
        }
    }

    public /* synthetic */ void lambda$cleanup$1$ContactsController() {
        this.migratingContacts = false;
        this.completedRequestsCount = 0;
    }

    public void checkInviteText() {
        SharedPreferences preferences = MessagesController.getMainSettings(this.currentAccount);
        this.inviteLink = preferences.getString("invitelink", null);
        int time = preferences.getInt("invitelinktime", 0);
        if (this.updatingInviteLink) {
            return;
        }
        if (this.inviteLink == null || Math.abs((System.currentTimeMillis() / 1000) - ((long) time)) >= 86400) {
            this.updatingInviteLink = true;
            TLRPC.TL_help_getInviteText req = new TLRPC.TL_help_getInviteText();
            getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ContactsController$Wn5VSEZdotHOg3IX_bqXFVqqzdo
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$checkInviteText$3$ContactsController(tLObject, tL_error);
                }
            }, 2);
        }
    }

    public /* synthetic */ void lambda$checkInviteText$3$ContactsController(TLObject response, TLRPC.TL_error error) {
        if (response != null) {
            final TLRPC.TL_help_inviteText res = (TLRPC.TL_help_inviteText) response;
            if (res.message.length() != 0) {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ContactsController$mVicUjSJBFtxFMWik0VfGoUF-Zg
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$2$ContactsController(res);
                    }
                });
            }
        }
    }

    public /* synthetic */ void lambda$null$2$ContactsController(TLRPC.TL_help_inviteText res) {
        this.updatingInviteLink = false;
        SharedPreferences preferences1 = MessagesController.getMainSettings(this.currentAccount);
        SharedPreferences.Editor editor = preferences1.edit();
        String str = res.message;
        this.inviteLink = str;
        editor.putString("invitelink", str);
        editor.putInt("invitelinktime", (int) (System.currentTimeMillis() / 1000));
        editor.commit();
    }

    public String getInviteText(int contacts) {
        String link = this.inviteLink;
        if (link == null) {
            link = "https://m12345.com/dl";
        }
        if (contacts <= 1) {
            return LocaleController.formatString("InviteText2", mpEIGo.juqQQs.esbSDO.R.string.InviteText2, link);
        }
        try {
            return String.format(LocaleController.getPluralString("InviteTextNum", contacts), Integer.valueOf(contacts), link);
        } catch (Exception e) {
            return LocaleController.formatString("InviteText2", mpEIGo.juqQQs.esbSDO.R.string.InviteText2, link);
        }
    }

    public void checkAppAccount() {
        AccountManager am = AccountManager.get(ApplicationLoader.applicationContext);
        try {
            Account[] accounts = am.getAccountsByType("im.uwrkaxlmjj.messenger");
            this.systemAccount = null;
            for (int a = 0; a < accounts.length; a++) {
                Account acc = accounts[a];
                boolean found = false;
                int b = 0;
                while (true) {
                    if (b >= 3) {
                        break;
                    }
                    TLRPC.User user = UserConfig.getInstance(b).getCurrentUser();
                    if (user != null) {
                        if (acc.name.equals("" + user.id)) {
                            if (b == this.currentAccount) {
                                this.systemAccount = acc;
                            }
                            found = true;
                        }
                    }
                    b++;
                }
                if (!found) {
                    try {
                        am.removeAccount(accounts[a], null, null);
                    } catch (Exception e) {
                    }
                }
            }
        } catch (Throwable th) {
        }
        if (getUserConfig().isClientActivated()) {
            readContacts();
            if (this.systemAccount == null) {
                try {
                    Account account = new Account("" + getUserConfig().getClientUserId(), "im.uwrkaxlmjj.messenger");
                    this.systemAccount = account;
                    am.addAccountExplicitly(account, "", null);
                } catch (Exception e2) {
                }
            }
        }
    }

    public void deleteUnknownAppAccounts() {
        try {
            this.systemAccount = null;
            AccountManager am = AccountManager.get(ApplicationLoader.applicationContext);
            Account[] accounts = am.getAccountsByType("im.uwrkaxlmjj.messenger");
            for (int a = 0; a < accounts.length; a++) {
                Account acc = accounts[a];
                boolean found = false;
                int b = 0;
                while (true) {
                    if (b >= 3) {
                        break;
                    }
                    TLRPC.User user = UserConfig.getInstance(b).getCurrentUser();
                    if (user != null) {
                        if (acc.name.equals("" + user.id)) {
                            found = true;
                            break;
                        }
                    }
                    b++;
                }
                if (!found) {
                    try {
                        am.removeAccount(accounts[a], null, null);
                    } catch (Exception e) {
                    }
                }
            }
        } catch (Exception e2) {
            e2.printStackTrace();
        }
    }

    public void checkContacts() {
        Utilities.globalQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ContactsController$xtGvoP9aSVV_iASDeraCFEx7AVE
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$checkContacts$4$ContactsController();
            }
        });
    }

    public /* synthetic */ void lambda$checkContacts$4$ContactsController() {
        if (checkContactsInternal()) {
            if (BuildVars.LOGS_ENABLED) {
                FileLog.d("detected contacts change");
            }
            performSyncPhoneBook(getContactsCopy(this.contactsBook), true, false, true, false, true, false);
        }
    }

    public void forceImportContacts() {
        Utilities.globalQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ContactsController$EH_TLSSQrsVHwc4kZ8rMzILdse0
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$forceImportContacts$5$ContactsController();
            }
        });
    }

    public /* synthetic */ void lambda$forceImportContacts$5$ContactsController() {
        if (BuildVars.LOGS_ENABLED) {
            FileLog.d("force import contacts");
        }
        performSyncPhoneBook(new HashMap<>(), true, true, true, true, false, false);
    }

    public void syncPhoneBookByAlert(final HashMap<String, Contact> contacts, final boolean first, final boolean schedule, final boolean cancel) {
        Utilities.globalQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ContactsController$zT-8WIJ57VZE3TZ8EpUZJxTysdI
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$syncPhoneBookByAlert$6$ContactsController(contacts, first, schedule, cancel);
            }
        });
    }

    public /* synthetic */ void lambda$syncPhoneBookByAlert$6$ContactsController(HashMap contacts, boolean first, boolean schedule, boolean cancel) {
        if (BuildVars.LOGS_ENABLED) {
            FileLog.d("sync contacts by alert");
        }
        performSyncPhoneBook(contacts, true, first, schedule, false, false, cancel);
    }

    public void deleteAllContacts(final Runnable runnable) {
        resetImportedContacts();
        TLRPC.TL_contacts_deleteContacts req = new TLRPC.TL_contacts_deleteContacts();
        int size = this.contacts.size();
        for (int a = 0; a < size; a++) {
            TLRPC.Contact contact = this.contacts.get(a);
            req.id.add(getMessagesController().getInputUser(contact.user_id));
        }
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ContactsController$VqnqPmHnT8v7hA3S-xb59guzNI0
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$deleteAllContacts$8$ContactsController(runnable, tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$deleteAllContacts$8$ContactsController(final Runnable runnable, TLObject response, TLRPC.TL_error error) {
        if (error == null) {
            this.contactsBookSPhones.clear();
            this.contactsBook.clear();
            this.completedRequestsCount = 0;
            this.migratingContacts = false;
            this.contactsSyncInProgress = false;
            this.contactsLoaded = false;
            this.loadingContacts = false;
            this.contactsBookLoaded = false;
            this.lastContactsVersions = "";
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ContactsController$y2jqplL48qafaUAzwVx-Y1EiNWE
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$7$ContactsController(runnable);
                }
            });
            return;
        }
        AndroidUtilities.runOnUIThread(runnable);
    }

    public /* synthetic */ void lambda$null$7$ContactsController(Runnable runnable) {
        AccountManager am = AccountManager.get(ApplicationLoader.applicationContext);
        try {
            Account[] accounts = am.getAccountsByType("im.uwrkaxlmjj.messenger");
            this.systemAccount = null;
            for (Account acc : accounts) {
                int b = 0;
                while (true) {
                    if (b >= 3) {
                        break;
                    }
                    TLRPC.User user = UserConfig.getInstance(b).getCurrentUser();
                    if (user != null) {
                        if (acc.name.equals("" + user.id)) {
                            am.removeAccount(acc, null, null);
                            break;
                        }
                    }
                    b++;
                }
            }
        } catch (Throwable th) {
        }
        try {
            Account account = new Account("" + getUserConfig().getClientUserId(), "im.uwrkaxlmjj.messenger");
            this.systemAccount = account;
            am.addAccountExplicitly(account, "", null);
        } catch (Exception e) {
        }
        getMessagesStorage().putCachedPhoneBook(new HashMap<>(), false, true);
        getMessagesStorage().putContacts(new ArrayList<>(), true);
        this.phoneBookContacts.clear();
        this.contacts.clear();
        this.contactsDict.clear();
        this.usersSectionsDict.clear();
        this.usersMutualSectionsDict.clear();
        this.sortedUsersSectionsArray.clear();
        this.phoneBookSectionsDict.clear();
        this.phoneBookSectionsArray.clear();
        this.delayedContactsUpdate.clear();
        this.sortedUsersMutualSectionsArray.clear();
        this.contactsByPhone.clear();
        this.contactsByShortPhone.clear();
        getNotificationCenter().postNotificationName(NotificationCenter.contactsDidLoad, new Object[0]);
        loadContacts(false, 0);
        runnable.run();
    }

    public void resetImportedContacts() {
        TLRPC.TL_contacts_resetSaved req = new TLRPC.TL_contacts_resetSaved();
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ContactsController$BlKF5Y8o6jTK29m7kWXNcj3aUoE
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                ContactsController.lambda$resetImportedContacts$9(tLObject, tL_error);
            }
        });
    }

    static /* synthetic */ void lambda$resetImportedContacts$9(TLObject response, TLRPC.TL_error error) {
    }

    private boolean checkContactsInternal() {
        boolean reload = false;
        try {
        } catch (Exception e) {
            FileLog.e(e);
        }
        if (!hasContactsPermission()) {
            return false;
        }
        ContentResolver cr = ApplicationLoader.applicationContext.getContentResolver();
        try {
            Cursor pCur = cr.query(ContactsContract.RawContacts.CONTENT_URI, new String[]{"version"}, null, null, null);
            if (pCur != null) {
                try {
                    StringBuilder currentVersion = new StringBuilder();
                    while (pCur.moveToNext()) {
                        currentVersion.append(pCur.getString(pCur.getColumnIndex("version")));
                    }
                    String newContactsVersion = currentVersion.toString();
                    if (this.lastContactsVersions.length() != 0 && !this.lastContactsVersions.equals(newContactsVersion)) {
                        reload = true;
                    }
                    this.lastContactsVersions = newContactsVersion;
                } finally {
                }
            }
            if (pCur != null) {
                pCur.close();
            }
        } catch (Exception e2) {
            FileLog.e(e2);
        }
        return reload;
    }

    public void readContacts() {
        synchronized (this.loadContactsSync) {
            if (this.loadingContacts) {
                return;
            }
            this.loadingContacts = true;
            Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ContactsController$itRVhKl27iJcih1n9q_7BEZJ7PE
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$readContacts$10$ContactsController();
                }
            });
        }
    }

    public /* synthetic */ void lambda$readContacts$10$ContactsController() {
        if (!this.contacts.isEmpty() || this.contactsLoaded) {
            synchronized (this.loadContactsSync) {
                this.loadingContacts = false;
            }
            return;
        }
        loadContacts(true, 0);
    }

    public void syncRemoteContacts() {
        synchronized (this.loadContactsSync) {
            if (this.loadingContacts) {
                return;
            }
            this.loadingContacts = true;
            loadContacts(false, getContactsHash(this.contacts));
        }
    }

    private boolean isNotValidNameString(String src) {
        if (TextUtils.isEmpty(src)) {
            return true;
        }
        int count = 0;
        int len = src.length();
        for (int a = 0; a < len; a++) {
            char c = src.charAt(a);
            if (c >= '0' && c <= '9') {
                count++;
            }
        }
        return count > 3;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:183:0x038a A[Catch: all -> 0x039d, TRY_LEAVE, TryCatch #5 {all -> 0x039d, blocks: (B:181:0x0385, B:183:0x038a), top: B:211:0x0385 }] */
    /* JADX WARN: Removed duplicated region for block: B:185:0x038f A[Catch: Exception -> 0x0375, TRY_ENTER, TRY_LEAVE, TryCatch #4 {Exception -> 0x0375, blocks: (B:170:0x0371, B:185:0x038f), top: B:209:0x0030 }] */
    /* JADX WARN: Removed duplicated region for block: B:188:0x0395  */
    /* JADX WARN: Removed duplicated region for block: B:189:0x0397  */
    /* JADX WARN: Type inference failed for: r0v14, types: [java.util.HashMap] */
    /* JADX WARN: Type inference failed for: r10v1 */
    /* JADX WARN: Type inference failed for: r10v2, types: [boolean, int] */
    /* JADX WARN: Type inference failed for: r10v3 */
    /* JADX WARN: Type inference failed for: r10v4 */
    /* JADX WARN: Type inference failed for: r10v6 */
    /* JADX WARN: Type inference failed for: r17v1, types: [java.lang.CharSequence, java.lang.Object, java.lang.String] */
    /* JADX WARN: Type inference failed for: r2v0 */
    /* JADX WARN: Type inference failed for: r2v1 */
    /* JADX WARN: Type inference failed for: r2v10 */
    /* JADX WARN: Type inference failed for: r2v11 */
    /* JADX WARN: Type inference failed for: r2v12 */
    /* JADX WARN: Type inference failed for: r2v2, types: [android.database.Cursor] */
    /* JADX WARN: Type inference failed for: r2v3, types: [android.database.Cursor] */
    /* JADX WARN: Type inference failed for: r2v4 */
    /* JADX WARN: Type inference failed for: r2v5 */
    /* JADX WARN: Type inference failed for: r2v6 */
    /* JADX WARN: Type inference failed for: r2v7 */
    /* JADX WARN: Type inference failed for: r2v8, types: [android.database.Cursor] */
    /* JADX WARN: Type inference failed for: r2v9, types: [android.database.Cursor] */
    /* JADX WARN: Type inference failed for: r7v3 */
    /* JADX WARN: Type inference failed for: r7v4, types: [java.lang.Object] */
    /* JADX WARN: Type inference failed for: r7v7 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private java.util.HashMap<java.lang.String, im.uwrkaxlmjj.messenger.ContactsController.Contact> readContactsFromPhoneBook() {
        /*
            Method dump skipped, instruction units count: 942
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.ContactsController.readContactsFromPhoneBook():java.util.HashMap");
    }

    public HashMap<String, Contact> getContactsCopy(HashMap<String, Contact> original) {
        HashMap<String, Contact> ret = new HashMap<>();
        for (Map.Entry<String, Contact> entry : original.entrySet()) {
            Contact copyContact = new Contact();
            Contact originalContact = entry.getValue();
            copyContact.phoneDeleted.addAll(originalContact.phoneDeleted);
            copyContact.phones.addAll(originalContact.phones);
            copyContact.phoneTypes.addAll(originalContact.phoneTypes);
            copyContact.shortPhones.addAll(originalContact.shortPhones);
            copyContact.first_name = originalContact.first_name;
            copyContact.last_name = originalContact.last_name;
            copyContact.contact_id = originalContact.contact_id;
            copyContact.key = originalContact.key;
            ret.put(copyContact.key, copyContact);
        }
        return ret;
    }

    protected void migratePhoneBookToV7(final SparseArray<Contact> contactHashMap) {
        Utilities.globalQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ContactsController$EhhL7c-u5pHdICKMRuEMQt3oLAk
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$migratePhoneBookToV7$11$ContactsController(contactHashMap);
            }
        });
    }

    public /* synthetic */ void lambda$migratePhoneBookToV7$11$ContactsController(SparseArray contactHashMap) {
        if (this.migratingContacts) {
            return;
        }
        this.migratingContacts = true;
        HashMap<String, Contact> migratedMap = new HashMap<>();
        HashMap<String, Contact> contactsMap = readContactsFromPhoneBook();
        HashMap<String, String> contactsBookShort = new HashMap<>();
        for (Map.Entry<String, Contact> entry : contactsMap.entrySet()) {
            Contact value = entry.getValue();
            for (int a = 0; a < value.shortPhones.size(); a++) {
                contactsBookShort.put(value.shortPhones.get(a), value.key);
            }
        }
        for (int b = 0; b < contactHashMap.size(); b++) {
            Contact value2 = (Contact) contactHashMap.valueAt(b);
            int a2 = 0;
            while (true) {
                if (a2 < value2.shortPhones.size()) {
                    String sphone = value2.shortPhones.get(a2);
                    String key = contactsBookShort.get(sphone);
                    if (key == null) {
                        a2++;
                    } else {
                        value2.key = key;
                        migratedMap.put(key, value2);
                        break;
                    }
                }
            }
        }
        if (BuildVars.LOGS_ENABLED) {
            FileLog.d("migrated contacts " + migratedMap.size() + " of " + contactHashMap.size());
        }
        getMessagesStorage().putCachedPhoneBook(migratedMap, true, false);
    }

    public void checkPhonebookUsers() {
        Utilities.globalQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ContactsController$75ozYrFP2urev8gsE6NEGF5dbzA
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$checkPhonebookUsers$14$ContactsController();
            }
        });
    }

    public /* synthetic */ void lambda$checkPhonebookUsers$14$ContactsController() {
        HashMap<String, Contact> contactsMap = readContactsFromPhoneBook();
        ArrayList<TLRPC.TL_inputPhoneContact> toImport = new ArrayList<>();
        final HashMap<String, TLRPC.TL_inputPhoneContact> inputPhoneContactsMap = new HashMap<>();
        for (Map.Entry<String, Contact> pair : contactsMap.entrySet()) {
            Contact value = pair.getValue();
            pair.getKey();
            for (int a = 0; a < value.phones.size(); a++) {
                TLRPC.TL_inputPhoneContact imp = new TLRPC.TL_inputPhoneContact();
                imp.client_id = value.contact_id;
                imp.client_id |= ((long) a) << 32;
                imp.first_name = value.first_name;
                imp.last_name = value.last_name;
                imp.phone = value.phones.get(a);
                toImport.add(imp);
                inputPhoneContactsMap.put(value.phones.get(a), imp);
            }
        }
        this.completedRequestsCount = 0;
        final ArrayList<TLRPC.User> userList = new ArrayList<>();
        final int count = (int) Math.ceil(((double) toImport.size()) / 500.0d);
        for (int a2 = 0; a2 < count; a2++) {
            TLRPC.TL_contacts_importContacts req = new TLRPC.TL_contacts_importContacts();
            int start = a2 * SlidingItemMenuRecyclerView.DEFAULT_ITEM_SCROLL_DURATION;
            int end = Math.min(start + SlidingItemMenuRecyclerView.DEFAULT_ITEM_SCROLL_DURATION, toImport.size());
            req.contacts = new ArrayList<>(toImport.subList(start, end));
            getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ContactsController$L4N_JyRS_nzZibmh1TZMEy2Brus
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$null$13$ContactsController(userList, count, inputPhoneContactsMap, tLObject, tL_error);
                }
            }, 6);
        }
    }

    public /* synthetic */ void lambda$null$13$ContactsController(final ArrayList userList, int count, final HashMap inputPhoneContactsMap, TLObject response, TLRPC.TL_error error) {
        this.completedRequestsCount++;
        if (error == null) {
            if (BuildVars.LOGS_ENABLED) {
                FileLog.d("contacts imported");
            }
            TLRPC.TL_contacts_importedContacts res = (TLRPC.TL_contacts_importedContacts) response;
            if (res.users != null && !res.users.isEmpty()) {
                userList.addAll(res.users);
            }
        }
        if (this.completedRequestsCount == count) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ContactsController$fSOPV9oAxsuMJ5eilZouVzeInVI
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$12$ContactsController(userList, inputPhoneContactsMap);
                }
            });
        }
    }

    public /* synthetic */ void lambda$null$12$ContactsController(ArrayList userList, HashMap inputPhoneContactsMap) {
        getNotificationCenter().postNotificationName(NotificationCenter.contactAboutPhonebookLoaded, userList, inputPhoneContactsMap);
    }

    protected void performSyncPhoneBook(final HashMap<String, Contact> contactHashMap, final boolean request, final boolean first, final boolean schedule, final boolean force, final boolean checkCount, final boolean canceled) {
        if (!first && !this.contactsBookLoaded) {
            return;
        }
        Utilities.globalQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ContactsController$hNmpQLuYHEwan8pzpVsTve1PHhk
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$performSyncPhoneBook$27$ContactsController(contactHashMap, schedule, request, first, force, checkCount, canceled);
            }
        });
    }

    /* JADX WARN: Removed duplicated region for block: B:118:0x02de  */
    /* JADX WARN: Removed duplicated region for block: B:124:0x0333 A[ADDED_TO_REGION, REMOVE] */
    /* JADX WARN: Removed duplicated region for block: B:128:0x034b  */
    /* JADX WARN: Removed duplicated region for block: B:135:0x0387  */
    /* JADX WARN: Removed duplicated region for block: B:146:0x03d2  */
    /* JADX WARN: Removed duplicated region for block: B:272:0x03d5 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:42:0x0149  */
    /* JADX WARN: Removed duplicated region for block: B:44:0x014f  */
    /* JADX WARN: Removed duplicated region for block: B:55:0x017a  */
    /* JADX WARN: Removed duplicated region for block: B:58:0x017f A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:86:0x022e  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public /* synthetic */ void lambda$performSyncPhoneBook$27$ContactsController(final java.util.HashMap r35, final boolean r36, boolean r37, final boolean r38, boolean r39, boolean r40, boolean r41) {
        /*
            Method dump skipped, instruction units count: 1843
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.ContactsController.lambda$performSyncPhoneBook$27$ContactsController(java.util.HashMap, boolean, boolean, boolean, boolean, boolean, boolean):void");
    }

    public /* synthetic */ void lambda$null$15$ContactsController(HashMap contactHashMap) {
        ArrayList<TLRPC.User> toDelete = new ArrayList<>();
        if (contactHashMap != null && !contactHashMap.isEmpty()) {
            try {
                HashMap<String, TLRPC.User> contactsPhonesShort = new HashMap<>();
                for (int a = 0; a < this.contacts.size(); a++) {
                    TLRPC.Contact value = this.contacts.get(a);
                    TLRPC.User user = getMessagesController().getUser(Integer.valueOf(value.user_id));
                    if (user != null && !TextUtils.isEmpty(user.phone)) {
                        contactsPhonesShort.put(user.phone, user);
                    }
                }
                int removed = 0;
                for (Map.Entry<String, Contact> entry : contactHashMap.entrySet()) {
                    Contact contact = entry.getValue();
                    boolean was = false;
                    int a2 = 0;
                    while (a2 < contact.shortPhones.size()) {
                        String phone = contact.shortPhones.get(a2);
                        TLRPC.User user2 = contactsPhonesShort.get(phone);
                        if (user2 != null) {
                            was = true;
                            toDelete.add(user2);
                            contact.shortPhones.remove(a2);
                            a2--;
                        }
                        a2++;
                    }
                    if (!was || contact.shortPhones.size() == 0) {
                        removed++;
                    }
                }
            } catch (Exception e) {
                FileLog.e(e);
            }
        }
        if (!toDelete.isEmpty()) {
            deleteContact(toDelete);
        }
    }

    public /* synthetic */ void lambda$null$16$ContactsController(int checkType, HashMap contactHashMap, boolean first, boolean schedule) {
        getNotificationCenter().postNotificationName(NotificationCenter.hasNewContactsToImport, Integer.valueOf(checkType), contactHashMap, Boolean.valueOf(first), Boolean.valueOf(schedule));
    }

    public /* synthetic */ void lambda$null$18$ContactsController(HashMap contactsBookShort, HashMap contactsMap, boolean first, final HashMap phoneBookSectionsDictFinal, final ArrayList phoneBookSectionsArrayFinal, final HashMap phoneBookByShortPhonesFinal) {
        this.contactsBookSPhones = contactsBookShort;
        this.contactsBook = contactsMap;
        this.contactsSyncInProgress = false;
        this.contactsBookLoaded = true;
        if (first) {
            this.contactsLoaded = true;
        }
        if (!this.delayedContactsUpdate.isEmpty() && this.contactsLoaded) {
            applyContactsUpdates(this.delayedContactsUpdate, null, null, null);
            this.delayedContactsUpdate.clear();
        }
        getMessagesStorage().putCachedPhoneBook(contactsMap, false, false);
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ContactsController$IVi9fejsuo9uEZoBHz_OTNkmzXQ
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$17$ContactsController(phoneBookSectionsDictFinal, phoneBookSectionsArrayFinal, phoneBookByShortPhonesFinal);
            }
        });
    }

    public /* synthetic */ void lambda$null$17$ContactsController(HashMap phoneBookSectionsDictFinal, ArrayList phoneBookSectionsArrayFinal, HashMap phoneBookByShortPhonesFinal) {
        lambda$null$25$ContactsController(phoneBookSectionsDictFinal, phoneBookSectionsArrayFinal, phoneBookByShortPhonesFinal);
        updateUnregisteredContacts();
        getNotificationCenter().postNotificationName(NotificationCenter.contactsDidLoad, new Object[0]);
        getNotificationCenter().postNotificationName(NotificationCenter.contactsImported, new Object[0]);
    }

    public /* synthetic */ void lambda$null$22$ContactsController(HashMap contactsMapToSave, SparseArray contactIdToKey, final boolean[] hasErrors, final HashMap contactsMap, TLRPC.TL_contacts_importContacts req, int count, final HashMap contactsBookShort, final boolean first, final HashMap phoneBookSectionsDictFinal, final ArrayList phoneBookSectionsArrayFinal, final HashMap phoneBookByShortPhonesFinal, TLObject response, TLRPC.TL_error error) {
        this.completedRequestsCount++;
        if (error == null) {
            if (BuildVars.LOGS_ENABLED) {
                FileLog.d("contacts imported");
            }
            TLRPC.TL_contacts_importedContacts res = (TLRPC.TL_contacts_importedContacts) response;
            if (!res.retry_contacts.isEmpty()) {
                for (int a1 = 0; a1 < res.retry_contacts.size(); a1++) {
                    long id = res.retry_contacts.get(a1).longValue();
                    contactsMapToSave.remove(contactIdToKey.get((int) id));
                }
                hasErrors[0] = true;
                if (BuildVars.LOGS_ENABLED) {
                    FileLog.d("result has retry contacts");
                }
            }
            for (int a12 = 0; a12 < res.popular_invites.size(); a12++) {
                TLRPC.TL_popularContact popularContact = res.popular_invites.get(a12);
                Contact contact = (Contact) contactsMap.get(contactIdToKey.get((int) popularContact.client_id));
                if (contact != null) {
                    contact.imported = popularContact.importers;
                }
            }
            getMessagesStorage().putUsersAndChats(res.users, null, true, true);
            ArrayList<TLRPC.Contact> cArr = new ArrayList<>();
            for (int a13 = 0; a13 < res.imported.size(); a13++) {
                TLRPC.Contact contact2 = new TLRPC.Contact();
                contact2.user_id = res.imported.get(a13).user_id;
                cArr.add(contact2);
            }
            processLoadedContacts(cArr, res.users, 2);
        } else {
            for (int a14 = 0; a14 < req.contacts.size(); a14++) {
                contactsMapToSave.remove(contactIdToKey.get((int) req.contacts.get(a14).client_id));
            }
            hasErrors[0] = true;
            if (BuildVars.LOGS_ENABLED) {
                FileLog.d("import contacts error " + error.text);
            }
        }
        if (this.completedRequestsCount == count) {
            if (!contactsMapToSave.isEmpty()) {
                getMessagesStorage().putCachedPhoneBook(contactsMapToSave, false, false);
            }
            Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ContactsController$YdalBmgGt2cq0s1GX7ZGoYDYnVk
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$21$ContactsController(contactsBookShort, contactsMap, first, phoneBookSectionsDictFinal, phoneBookSectionsArrayFinal, phoneBookByShortPhonesFinal, hasErrors);
                }
            });
        }
    }

    public /* synthetic */ void lambda$null$21$ContactsController(HashMap contactsBookShort, HashMap contactsMap, boolean first, final HashMap phoneBookSectionsDictFinal, final ArrayList phoneBookSectionsArrayFinal, final HashMap phoneBookByShortPhonesFinal, boolean[] hasErrors) {
        this.contactsBookSPhones = contactsBookShort;
        this.contactsBook = contactsMap;
        this.contactsSyncInProgress = false;
        this.contactsBookLoaded = true;
        if (first) {
            this.contactsLoaded = true;
        }
        if (!this.delayedContactsUpdate.isEmpty() && this.contactsLoaded) {
            applyContactsUpdates(this.delayedContactsUpdate, null, null, null);
            this.delayedContactsUpdate.clear();
        }
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ContactsController$g7mMbYPJxO5_nLOxWOVKhfNVAPU
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$19$ContactsController(phoneBookSectionsDictFinal, phoneBookSectionsArrayFinal, phoneBookByShortPhonesFinal);
            }
        });
        if (hasErrors[0]) {
            Utilities.globalQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ContactsController$rpL8dkPZUYrUuHpVygtdJ4P7R9g
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$20$ContactsController();
                }
            }, 300000L);
        }
    }

    public /* synthetic */ void lambda$null$19$ContactsController(HashMap phoneBookSectionsDictFinal, ArrayList phoneBookSectionsArrayFinal, HashMap phoneBookByShortPhonesFinal) {
        lambda$null$25$ContactsController(phoneBookSectionsDictFinal, phoneBookSectionsArrayFinal, phoneBookByShortPhonesFinal);
        getNotificationCenter().postNotificationName(NotificationCenter.contactsImported, new Object[0]);
    }

    public /* synthetic */ void lambda$null$20$ContactsController() {
        getMessagesStorage().getCachedPhoneBook(true);
    }

    public /* synthetic */ void lambda$null$24$ContactsController(HashMap contactsBookShort, HashMap contactsMap, boolean first, final HashMap phoneBookSectionsDictFinal, final ArrayList phoneBookSectionsArrayFinal, final HashMap phoneBookByShortPhonesFinal) {
        this.contactsBookSPhones = contactsBookShort;
        this.contactsBook = contactsMap;
        this.contactsSyncInProgress = false;
        this.contactsBookLoaded = true;
        if (first) {
            this.contactsLoaded = true;
        }
        if (!this.delayedContactsUpdate.isEmpty() && this.contactsLoaded) {
            applyContactsUpdates(this.delayedContactsUpdate, null, null, null);
            this.delayedContactsUpdate.clear();
        }
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ContactsController$DXb4-lfT2DPKRUesaSRz2lDI-P0
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$23$ContactsController(phoneBookSectionsDictFinal, phoneBookSectionsArrayFinal, phoneBookByShortPhonesFinal);
            }
        });
    }

    public /* synthetic */ void lambda$null$23$ContactsController(HashMap phoneBookSectionsDictFinal, ArrayList phoneBookSectionsArrayFinal, HashMap phoneBookByShortPhonesFinal) {
        lambda$null$25$ContactsController(phoneBookSectionsDictFinal, phoneBookSectionsArrayFinal, phoneBookByShortPhonesFinal);
        updateUnregisteredContacts();
        getNotificationCenter().postNotificationName(NotificationCenter.contactsDidLoad, new Object[0]);
        getNotificationCenter().postNotificationName(NotificationCenter.contactsImported, new Object[0]);
    }

    public /* synthetic */ void lambda$null$26$ContactsController(HashMap contactsBookShort, HashMap contactsMap, boolean first, final HashMap phoneBookSectionsDictFinal, final ArrayList phoneBookSectionsArrayFinal, final HashMap phoneBookByShortPhonesFinal) {
        this.contactsBookSPhones = contactsBookShort;
        this.contactsBook = contactsMap;
        this.contactsSyncInProgress = false;
        this.contactsBookLoaded = true;
        if (first) {
            this.contactsLoaded = true;
        }
        if (!this.delayedContactsUpdate.isEmpty() && this.contactsLoaded && this.contactsBookLoaded) {
            applyContactsUpdates(this.delayedContactsUpdate, null, null, null);
            this.delayedContactsUpdate.clear();
        }
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ContactsController$veqUyq3FNqkeQQ77PWB29gpJtQA
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$25$ContactsController(phoneBookSectionsDictFinal, phoneBookSectionsArrayFinal, phoneBookByShortPhonesFinal);
            }
        });
    }

    public boolean isLoadingContacts() {
        boolean z;
        synchronized (this.loadContactsSync) {
            z = this.loadingContacts;
        }
        return z;
    }

    private int getContactsHash(ArrayList<TLRPC.Contact> contacts) {
        long j;
        long j2;
        long acc = 0;
        ArrayList<TLRPC.Contact> contacts2 = new ArrayList<>(contacts);
        Collections.sort(contacts2, new Comparator() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ContactsController$_6_F_ZBEjcWbRjtT4TKD5nkJJ7k
            @Override // java.util.Comparator
            public final int compare(Object obj, Object obj2) {
                return ContactsController.lambda$getContactsHash$28((TLRPC.Contact) obj, (TLRPC.Contact) obj2);
            }
        });
        int count = contacts2.size();
        for (int a = -1; a < count; a++) {
            if (a == -1) {
                j = (20261 * acc) + 2147483648L;
                j2 = getUserConfig().contactsSavedCount;
            } else {
                TLRPC.Contact set = contacts2.get(a);
                j = (20261 * acc) + 2147483648L;
                j2 = set.user_id;
            }
            acc = (j + j2) % 2147483648L;
        }
        int a2 = (int) acc;
        return a2;
    }

    static /* synthetic */ int lambda$getContactsHash$28(TLRPC.Contact tl_contact, TLRPC.Contact tl_contact2) {
        if (tl_contact.user_id > tl_contact2.user_id) {
            return 1;
        }
        if (tl_contact.user_id < tl_contact2.user_id) {
            return -1;
        }
        return 0;
    }

    public void loadContacts(boolean fromCache, final int hash) {
        synchronized (this.loadContactsSync) {
            this.loadingContacts = true;
        }
        if (fromCache) {
            if (BuildVars.LOGS_ENABLED) {
                FileLog.d("load contacts from cache");
            }
            getMessagesStorage().getContacts();
        } else {
            if (BuildVars.LOGS_ENABLED) {
                FileLog.d("load contacts from server");
            }
            TLRPCContacts.TL_getContactsV1 req = new TLRPCContacts.TL_getContactsV1();
            req.hash = hash;
            getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ContactsController$sydJkpLPjxpqA6F1i_FFDK59GjY
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$loadContacts$30$ContactsController(hash, tLObject, tL_error);
                }
            });
        }
    }

    public /* synthetic */ void lambda$loadContacts$30$ContactsController(int hash, TLObject response, TLRPC.TL_error error) {
        if (error == null) {
            TLRPC.contacts_Contacts res = (TLRPC.contacts_Contacts) response;
            if (hash != 0 && (res instanceof TLRPC.TL_contacts_contactsNotModified)) {
                this.contactsLoaded = true;
                if (!this.delayedContactsUpdate.isEmpty() && this.contactsBookLoaded) {
                    applyContactsUpdates(this.delayedContactsUpdate, null, null, null);
                    this.delayedContactsUpdate.clear();
                }
                getUserConfig().lastContactsSyncTime = (int) (System.currentTimeMillis() / 1000);
                getUserConfig().saveConfig(false);
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ContactsController$d9CLEBO_4_MN4BQQCOf4hjCr9LY
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$29$ContactsController();
                    }
                });
                if (BuildVars.LOGS_ENABLED) {
                    FileLog.d("load contacts don't change");
                    return;
                }
                return;
            }
            getUserConfig().contactsSavedCount = res.saved_count;
            getUserConfig().saveConfig(false);
            processLoadedContacts(res.contacts, res.users, 0);
        }
    }

    public /* synthetic */ void lambda$null$29$ContactsController() {
        synchronized (this.loadContactsSync) {
            this.loadingContacts = false;
        }
        getNotificationCenter().postNotificationName(NotificationCenter.contactsDidLoad, new Object[0]);
    }

    public void processLoadedContacts(final ArrayList<TLRPC.Contact> contactsArr, final ArrayList<TLRPC.User> usersArr, final int from) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ContactsController$G0Yc1-0xsyjeyNXOaSNkuip_dTA
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$processLoadedContacts$38$ContactsController(usersArr, from, contactsArr);
            }
        });
    }

    public /* synthetic */ void lambda$processLoadedContacts$38$ContactsController(final ArrayList usersArr, final int from, final ArrayList contactsArr) {
        getMessagesController().putUsers(usersArr, from == 1);
        final SparseArray<TLRPC.User> usersDict = new SparseArray<>();
        ArrayList<Integer> contactsToAdd = new ArrayList<>();
        final boolean isEmpty = contactsArr.isEmpty();
        if (!this.contacts.isEmpty()) {
            HashMap<Integer, TLRPC.Contact> remoteContactsMap = new HashMap<>();
            int a = 0;
            while (a < contactsArr.size()) {
                TLRPC.Contact contact = (TLRPC.Contact) contactsArr.get(a);
                remoteContactsMap.put(Integer.valueOf(contact.user_id), contact);
                if (this.contactsDict.get(Integer.valueOf(contact.user_id)) != null) {
                    contactsArr.remove(a);
                    a--;
                }
                a++;
            }
            int i = 0;
            while (i < this.contacts.size()) {
                if (remoteContactsMap.get(Integer.valueOf(this.contacts.get(i).user_id)) == null) {
                    this.contacts.remove(i);
                    i--;
                }
                i++;
            }
            contactsArr.addAll(this.contacts);
        }
        for (int a2 = 0; a2 < contactsArr.size(); a2++) {
            TLRPC.User user = getMessagesController().getUser(Integer.valueOf(((TLRPC.Contact) contactsArr.get(a2)).user_id));
            if (user != null) {
                usersDict.put(user.id, user);
                contactsToAdd.add(Integer.valueOf(user.id));
            }
        }
        Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ContactsController$_ye0_Rlq6J10mypl8-pgiGrOuUw
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$37$ContactsController(from, contactsArr, usersDict, usersArr, isEmpty);
            }
        });
    }

    public /* synthetic */ void lambda$null$37$ContactsController(final int from, final ArrayList contactsArr, final SparseArray usersDict, ArrayList usersArr, final boolean isEmpty) {
        HashMap<String, TLRPC.Contact> contactsByPhonesDict;
        HashMap<String, TLRPC.Contact> contactsByPhonesDictFinal;
        HashMap<String, TLRPC.Contact> contactsByPhonesDict2;
        String key;
        ArrayList<TLRPC.Contact> arr;
        HashMap<String, TLRPC.Contact> contactsByPhonesShortDict;
        if (BuildVars.LOGS_ENABLED) {
            FileLog.d("done loading contactsfrom = " + from);
        }
        if (from == 1 && (contactsArr.isEmpty() || Math.abs((System.currentTimeMillis() / 1000) - ((long) getUserConfig().lastContactsSyncTime)) >= 7200)) {
            loadContacts(false, getContactsHash(contactsArr));
            if (contactsArr.isEmpty()) {
                return;
            }
        }
        if (from == 0) {
            getUserConfig().lastContactsSyncTime = (int) (System.currentTimeMillis() / 1000);
            getUserConfig().saveConfig(false);
        }
        for (int a = 0; a < contactsArr.size(); a++) {
            TLRPC.Contact contact = (TLRPC.Contact) contactsArr.get(a);
            if (usersDict.get(contact.user_id) == null && contact.user_id != getUserConfig().getClientUserId()) {
                loadContacts(false, 0);
                if (BuildVars.LOGS_ENABLED) {
                    FileLog.d("contacts are broken, load from server");
                    return;
                }
                return;
            }
        }
        if (from != 1) {
            getMessagesStorage().putUsersAndChats(usersArr, null, true, true);
            getMessagesStorage().putContacts(contactsArr, from != 2);
        }
        Collections.sort(contactsArr, new Comparator() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ContactsController$zd7vP-Itd5K1rSdOrfSiBYW1gl4
            @Override // java.util.Comparator
            public final int compare(Object obj, Object obj2) {
                return ContactsController.lambda$null$31(usersDict, (TLRPC.Contact) obj, (TLRPC.Contact) obj2);
            }
        });
        final ConcurrentHashMap<Integer, TLRPC.Contact> contactsDictionary = new ConcurrentHashMap<>(20, 1.0f, 2);
        final HashMap<String, ArrayList<TLRPC.Contact>> sectionsDict = new HashMap<>();
        final HashMap<String, ArrayList<TLRPC.Contact>> sectionsDictMutual = new HashMap<>();
        final ArrayList<String> sortedSectionsArray = new ArrayList<>();
        final ArrayList<String> sortedSectionsArrayMutual = new ArrayList<>();
        HashMap<String, TLRPC.Contact> contactsByPhonesShortDict2 = null;
        if (this.contactsBookLoaded) {
            contactsByPhonesDict = null;
        } else {
            HashMap<String, TLRPC.Contact> contactsByPhonesDict3 = new HashMap<>();
            contactsByPhonesShortDict2 = new HashMap<>();
            contactsByPhonesDict = contactsByPhonesDict3;
        }
        HashMap<String, TLRPC.Contact> contactsByPhonesDictFinal2 = contactsByPhonesDict;
        final HashMap<String, TLRPC.Contact> contactsByPhonesShortDictFinal = contactsByPhonesShortDict2;
        int a2 = 0;
        while (a2 < contactsArr.size()) {
            TLRPC.Contact value = (TLRPC.Contact) contactsArr.get(a2);
            TLRPC.User user = (TLRPC.User) usersDict.get(value.user_id);
            if (user == null) {
                contactsByPhonesDictFinal = contactsByPhonesDictFinal2;
                contactsByPhonesShortDict = contactsByPhonesShortDict2;
                contactsByPhonesDict2 = contactsByPhonesDict;
            } else {
                contactsByPhonesDictFinal = contactsByPhonesDictFinal2;
                contactsDictionary.put(Integer.valueOf(value.user_id), value);
                if (contactsByPhonesDict == null || TextUtils.isEmpty(user.phone)) {
                    contactsByPhonesDict2 = contactsByPhonesDict;
                } else {
                    contactsByPhonesDict.put(user.phone, value);
                    contactsByPhonesDict2 = contactsByPhonesDict;
                    contactsByPhonesShortDict2.put(user.phone.substring(Math.max(0, user.phone.length() - 7)), value);
                }
                String key2 = CharacterParser.getInstance().getSelling(UserObject.getFirstName(user));
                if (key2.length() > 1) {
                    key2 = key2.substring(0, 1);
                }
                if (key2.length() == 0) {
                    key = "#";
                } else {
                    key = key2.toUpperCase();
                }
                String replace = this.sectionsToReplace.get(key);
                if (replace != null) {
                    key = replace;
                }
                ArrayList<TLRPC.Contact> arr2 = sectionsDict.get(key);
                if (arr2 != null) {
                    arr = arr2;
                } else {
                    arr = new ArrayList<>();
                    sectionsDict.put(key, arr);
                    sortedSectionsArray.add(key);
                }
                arr.add(value);
                contactsByPhonesShortDict = contactsByPhonesShortDict2;
                if (user.mutual_contact) {
                    ArrayList<TLRPC.Contact> arr3 = sectionsDictMutual.get(key);
                    if (arr3 == null) {
                        arr3 = new ArrayList<>();
                        sectionsDictMutual.put(key, arr3);
                        sortedSectionsArrayMutual.add(key);
                    }
                    arr3.add(value);
                }
            }
            a2++;
            contactsByPhonesShortDict2 = contactsByPhonesShortDict;
            contactsByPhonesDictFinal2 = contactsByPhonesDictFinal;
            contactsByPhonesDict = contactsByPhonesDict2;
        }
        final HashMap<String, TLRPC.Contact> contactsByPhonesDictFinal3 = contactsByPhonesDictFinal2;
        Collections.sort(sortedSectionsArray, new Comparator() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ContactsController$i378s2KVNjClCHm-z2e3NM7lzwA
            @Override // java.util.Comparator
            public final int compare(Object obj, Object obj2) {
                return ContactsController.lambda$null$32((String) obj, (String) obj2);
            }
        });
        Collections.sort(sortedSectionsArrayMutual, new Comparator() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ContactsController$WWUIPMRsGkuCy3rJ-9MBF8qiuJ4
            @Override // java.util.Comparator
            public final int compare(Object obj, Object obj2) {
                return ContactsController.lambda$null$33((String) obj, (String) obj2);
            }
        });
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ContactsController$MXbjSq2gIB4zlhfC6YeJVYTckqc
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$34$ContactsController(contactsArr, contactsDictionary, sectionsDict, sectionsDictMutual, sortedSectionsArray, sortedSectionsArrayMutual, from, isEmpty);
            }
        });
        if (!this.delayedContactsUpdate.isEmpty() && this.contactsLoaded && this.contactsBookLoaded) {
            applyContactsUpdates(this.delayedContactsUpdate, null, null, null);
            this.delayedContactsUpdate.clear();
        }
        if (contactsByPhonesDictFinal3 != null) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ContactsController$lPkroaOsty9aEwfboAT1ngXJJ0A
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$36$ContactsController(contactsByPhonesDictFinal3, contactsByPhonesShortDictFinal);
                }
            });
        } else {
            this.contactsLoaded = true;
        }
    }

    static /* synthetic */ int lambda$null$31(SparseArray usersDict, TLRPC.Contact tl_contact, TLRPC.Contact tl_contact2) {
        TLRPC.User user1 = (TLRPC.User) usersDict.get(tl_contact.user_id);
        TLRPC.User user2 = (TLRPC.User) usersDict.get(tl_contact2.user_id);
        String name1 = UserObject.getFirstName(user1);
        String name2 = UserObject.getFirstName(user2);
        return name1.compareTo(name2);
    }

    static /* synthetic */ int lambda$null$32(String s, String s2) {
        char cv1 = s.charAt(0);
        char cv2 = s2.charAt(0);
        if (cv1 == '#') {
            return 1;
        }
        if (cv2 == '#') {
            return -1;
        }
        return s.compareTo(s2);
    }

    static /* synthetic */ int lambda$null$33(String s, String s2) {
        char cv1 = s.charAt(0);
        char cv2 = s2.charAt(0);
        if (cv1 == '#') {
            return 1;
        }
        if (cv2 == '#') {
            return -1;
        }
        return s.compareTo(s2);
    }

    public /* synthetic */ void lambda$null$34$ContactsController(ArrayList contactsArr, ConcurrentHashMap contactsDictionary, HashMap sectionsDict, HashMap sectionsDictMutual, ArrayList sortedSectionsArray, ArrayList sortedSectionsArrayMutual, int from, boolean isEmpty) {
        this.contacts = contactsArr;
        this.contactsDict = contactsDictionary;
        this.usersSectionsDict = sectionsDict;
        this.usersMutualSectionsDict = sectionsDictMutual;
        this.sortedUsersSectionsArray = sortedSectionsArray;
        this.sortedUsersMutualSectionsArray = sortedSectionsArrayMutual;
        if (from != 2) {
            synchronized (this.loadContactsSync) {
                this.loadingContacts = false;
            }
        }
        performWriteContactsToPhoneBook();
        updateUnregisteredContacts();
        getNotificationCenter().postNotificationName(NotificationCenter.contactsDidLoad, new Object[0]);
        if (from != 1 && !isEmpty) {
            saveContactsLoadTime();
        } else {
            reloadContactsStatusesMaybe();
        }
    }

    public /* synthetic */ void lambda$null$36$ContactsController(final HashMap contactsByPhonesDictFinal, final HashMap contactsByPhonesShortDictFinal) {
        Utilities.globalQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ContactsController$0oPoEt1Sq2d0UN1bftWGx3Wn6sc
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$35$ContactsController(contactsByPhonesDictFinal, contactsByPhonesShortDictFinal);
            }
        });
        if (this.contactsSyncInProgress) {
            return;
        }
        this.contactsSyncInProgress = true;
        getMessagesStorage().getCachedPhoneBook(false);
    }

    public /* synthetic */ void lambda$null$35$ContactsController(HashMap contactsByPhonesDictFinal, HashMap contactsByPhonesShortDictFinal) {
        this.contactsByPhone = contactsByPhonesDictFinal;
        this.contactsByShortPhone = contactsByPhonesShortDictFinal;
    }

    public boolean isContact(int uid) {
        return this.contactsDict.get(Integer.valueOf(uid)) != null;
    }

    private void reloadContactsStatusesMaybe() {
        try {
            SharedPreferences preferences = MessagesController.getMainSettings(this.currentAccount);
            long lastReloadStatusTime = preferences.getLong("lastReloadStatusTime", 0L);
            if (lastReloadStatusTime < System.currentTimeMillis() - 86400000) {
                reloadContactsStatuses();
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    private void saveContactsLoadTime() {
        try {
            SharedPreferences preferences = MessagesController.getMainSettings(this.currentAccount);
            preferences.edit().putLong("lastReloadStatusTime", System.currentTimeMillis()).commit();
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX INFO: renamed from: mergePhonebookAndAppContacts, reason: merged with bridge method [inline-methods] */
    public void lambda$null$25$ContactsController(final HashMap<String, ArrayList<Object>> phoneBookSectionsDictFinal, final ArrayList<String> phoneBookSectionsArrayFinal, final HashMap<String, Contact> phoneBookByShortPhonesFinal) {
        final ArrayList<TLRPC.Contact> contactsCopy = new ArrayList<>(this.contacts);
        Utilities.globalQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ContactsController$MmR6zG32tpHUQquWCwVq5_6DSQI
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$mergePhonebookAndAppContacts$42$ContactsController(contactsCopy, phoneBookByShortPhonesFinal, phoneBookSectionsDictFinal, phoneBookSectionsArrayFinal);
            }
        });
    }

    public /* synthetic */ void lambda$mergePhonebookAndAppContacts$42$ContactsController(ArrayList contactsCopy, HashMap phoneBookByShortPhonesFinal, final HashMap phoneBookSectionsDictFinal, final ArrayList phoneBookSectionsArrayFinal) {
        int size = contactsCopy.size();
        for (int a = 0; a < size; a++) {
            TLRPC.Contact value = (TLRPC.Contact) contactsCopy.get(a);
            TLRPC.User user = getMessagesController().getUser(Integer.valueOf(value.user_id));
            if (user != null && !TextUtils.isEmpty(user.phone)) {
                String phone = user.phone.substring(Math.max(0, user.phone.length() - 7));
                Contact contact = (Contact) phoneBookByShortPhonesFinal.get(phone);
                if (contact != null) {
                    if (contact.user == null) {
                        contact.user = user;
                    }
                } else {
                    String key = Contact.getLetter(user.first_name, user.last_name);
                    ArrayList<Object> arrayList = (ArrayList) phoneBookSectionsDictFinal.get(key);
                    if (arrayList == null) {
                        arrayList = new ArrayList<>();
                        phoneBookSectionsDictFinal.put(key, arrayList);
                        phoneBookSectionsArrayFinal.add(key);
                    }
                    arrayList.add(user);
                }
            }
        }
        Iterator it = phoneBookSectionsDictFinal.values().iterator();
        while (it.hasNext()) {
            Collections.sort((ArrayList) it.next(), new Comparator() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ContactsController$MpIUqJrwvic2E38qU7_h5CCQ_NI
                @Override // java.util.Comparator
                public final int compare(Object obj, Object obj2) {
                    return ContactsController.lambda$null$39(obj, obj2);
                }
            });
        }
        Collections.sort(phoneBookSectionsArrayFinal, new Comparator() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ContactsController$as8XzKKB77PYVNLHoftHWGuxvFQ
            @Override // java.util.Comparator
            public final int compare(Object obj, Object obj2) {
                return ContactsController.lambda$null$40((String) obj, (String) obj2);
            }
        });
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ContactsController$Q3jWfnBk-6pC7XN7UD__vnjhpNw
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$41$ContactsController(phoneBookSectionsArrayFinal, phoneBookSectionsDictFinal);
            }
        });
    }

    static /* synthetic */ int lambda$null$39(Object o1, Object o2) {
        String name1;
        String name2;
        if (o1 instanceof TLRPC.User) {
            TLRPC.User user = (TLRPC.User) o1;
            name1 = formatName(user.first_name, user.last_name);
        } else if (o1 instanceof Contact) {
            Contact contact = (Contact) o1;
            if (contact.user != null) {
                name1 = formatName(contact.user.first_name, contact.user.last_name);
            } else {
                String name12 = contact.first_name;
                name1 = formatName(name12, contact.last_name);
            }
        } else {
            name1 = "";
        }
        if (o2 instanceof TLRPC.User) {
            TLRPC.User user2 = (TLRPC.User) o2;
            name2 = formatName(user2.first_name, user2.last_name);
        } else if (o2 instanceof Contact) {
            Contact contact2 = (Contact) o2;
            if (contact2.user != null) {
                name2 = formatName(contact2.user.first_name, contact2.user.last_name);
            } else {
                String name22 = contact2.first_name;
                name2 = formatName(name22, contact2.last_name);
            }
        } else {
            name2 = "";
        }
        return name1.compareTo(name2);
    }

    static /* synthetic */ int lambda$null$40(String s, String s2) {
        char cv1 = s.charAt(0);
        char cv2 = s2.charAt(0);
        if (cv1 == '#') {
            return 1;
        }
        if (cv2 == '#') {
            return -1;
        }
        return s.compareTo(s2);
    }

    public /* synthetic */ void lambda$null$41$ContactsController(ArrayList phoneBookSectionsArrayFinal, HashMap phoneBookSectionsDictFinal) {
        this.phoneBookSectionsArray = phoneBookSectionsArrayFinal;
        this.phoneBookSectionsDict = phoneBookSectionsDictFinal;
    }

    private void updateUnregisteredContacts() {
        HashMap<String, TLRPC.Contact> contactsPhonesShort = new HashMap<>();
        int size = this.contacts.size();
        for (int a = 0; a < size; a++) {
            TLRPC.Contact value = this.contacts.get(a);
            TLRPC.User user = getMessagesController().getUser(Integer.valueOf(value.user_id));
            if (user != null && !TextUtils.isEmpty(user.phone)) {
                contactsPhonesShort.put(user.phone, value);
            }
        }
        ArrayList<Contact> sortedPhoneBookContacts = new ArrayList<>();
        for (Map.Entry<String, Contact> pair : this.contactsBook.entrySet()) {
            Contact value2 = pair.getValue();
            boolean skip = false;
            for (int a2 = 0; a2 < value2.phones.size(); a2++) {
                String sphone = value2.shortPhones.get(a2);
                if (contactsPhonesShort.containsKey(sphone) || value2.phoneDeleted.get(a2).intValue() == 1) {
                    skip = true;
                    break;
                }
            }
            if (!skip) {
                sortedPhoneBookContacts.add(value2);
            }
        }
        Collections.sort(sortedPhoneBookContacts, new Comparator() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ContactsController$lHUjpm5Y-254dGyIs8YxQDMXim0
            @Override // java.util.Comparator
            public final int compare(Object obj, Object obj2) {
                return ContactsController.lambda$updateUnregisteredContacts$43((ContactsController.Contact) obj, (ContactsController.Contact) obj2);
            }
        });
        this.phoneBookContacts = sortedPhoneBookContacts;
    }

    static /* synthetic */ int lambda$updateUnregisteredContacts$43(Contact contact, Contact contact2) {
        String toComapre1 = contact.first_name;
        if (toComapre1.length() == 0) {
            toComapre1 = contact.last_name;
        }
        String toComapre2 = contact2.first_name;
        if (toComapre2.length() == 0) {
            toComapre2 = contact2.last_name;
        }
        return toComapre1.compareTo(toComapre2);
    }

    private void buildContactsSectionsArrays(boolean sort) {
        String key;
        if (sort) {
            Collections.sort(this.contacts, new Comparator() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ContactsController$7DhWoZZIAVGXBtyjn8jPaQjJpLM
                @Override // java.util.Comparator
                public final int compare(Object obj, Object obj2) {
                    return this.f$0.lambda$buildContactsSectionsArrays$44$ContactsController((TLRPC.Contact) obj, (TLRPC.Contact) obj2);
                }
            });
        }
        HashMap<String, ArrayList<TLRPC.Contact>> sectionsDict = new HashMap<>();
        ArrayList<String> sortedSectionsArray = new ArrayList<>();
        for (int a = 0; a < this.contacts.size(); a++) {
            TLRPC.Contact value = this.contacts.get(a);
            TLRPC.User user = getMessagesController().getUser(Integer.valueOf(value.user_id));
            if (user != null) {
                String key2 = CharacterParser.getInstance().getSelling(UserObject.getFirstName(user));
                if (key2.length() > 1) {
                    key2 = key2.substring(0, 1);
                }
                if (key2.length() == 0) {
                    key = "#";
                } else {
                    key = key2.toUpperCase();
                }
                String replace = this.sectionsToReplace.get(key);
                if (replace != null) {
                    key = replace;
                }
                ArrayList<TLRPC.Contact> arr = sectionsDict.get(key);
                if (arr == null) {
                    arr = new ArrayList<>();
                    sectionsDict.put(key, arr);
                    sortedSectionsArray.add(key);
                }
                arr.add(value);
            }
        }
        Collections.sort(sortedSectionsArray, new Comparator() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ContactsController$vfIG6Nq0ff4hu17HOjiSSz6_mBI
            @Override // java.util.Comparator
            public final int compare(Object obj, Object obj2) {
                return ContactsController.lambda$buildContactsSectionsArrays$45((String) obj, (String) obj2);
            }
        });
        this.usersSectionsDict = sectionsDict;
        this.sortedUsersSectionsArray = sortedSectionsArray;
    }

    public /* synthetic */ int lambda$buildContactsSectionsArrays$44$ContactsController(TLRPC.Contact tl_contact, TLRPC.Contact tl_contact2) {
        TLRPC.User user1 = getMessagesController().getUser(Integer.valueOf(tl_contact.user_id));
        TLRPC.User user2 = getMessagesController().getUser(Integer.valueOf(tl_contact2.user_id));
        String name1 = UserObject.getFirstName(user1);
        String name2 = UserObject.getFirstName(user2);
        return name1.compareTo(name2);
    }

    static /* synthetic */ int lambda$buildContactsSectionsArrays$45(String s, String s2) {
        char cv1 = s.charAt(0);
        char cv2 = s2.charAt(0);
        if (cv1 == '#') {
            return 1;
        }
        if (cv2 == '#') {
            return -1;
        }
        return s.compareTo(s2);
    }

    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:19:0x0038 -> B:47:0x0055). Please report as a decompilation issue!!! */
    private boolean hasContactsPermission() {
        if (Build.VERSION.SDK_INT >= 23) {
            return ApplicationLoader.applicationContext.checkSelfPermission(PermissionUtils.LINKMAIN) == 0;
        }
        Cursor cursor = null;
        try {
            try {
                ContentResolver cr = ApplicationLoader.applicationContext.getContentResolver();
                cursor = cr.query(ContactsContract.CommonDataKinds.Phone.CONTENT_URI, this.projectionPhones, null, null, null);
            } catch (Throwable e) {
                try {
                    FileLog.e(e);
                    if (cursor != null) {
                        cursor.close();
                    }
                    return true;
                } finally {
                    if (cursor != null) {
                        try {
                            cursor.close();
                        } catch (Exception e2) {
                            FileLog.e(e2);
                        }
                    }
                }
            }
        } catch (Exception e3) {
            FileLog.e(e3);
        }
        if (cursor != null) {
            if (cursor.getCount() != 0) {
                if (cursor != null) {
                    cursor.close();
                }
                return true;
            }
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX INFO: renamed from: performWriteContactsToPhoneBookInternal, reason: merged with bridge method [inline-methods] */
    public void lambda$performWriteContactsToPhoneBook$46$ContactsController(ArrayList<TLRPC.Contact> contactsArray) {
        Cursor cursor = null;
        try {
            try {
                if (!hasContactsPermission()) {
                    if (0 != 0) {
                        cursor.close();
                        return;
                    }
                    return;
                }
                Uri rawContactUri = ContactsContract.RawContacts.CONTENT_URI.buildUpon().appendQueryParameter("account_name", this.systemAccount.name).appendQueryParameter("account_type", this.systemAccount.type).build();
                cursor = ApplicationLoader.applicationContext.getContentResolver().query(rawContactUri, new String[]{"_id", "sync2"}, null, null, null);
                SparseLongArray bookContacts = new SparseLongArray();
                if (cursor != null) {
                    while (cursor.moveToNext()) {
                        bookContacts.put(cursor.getInt(1), cursor.getLong(0));
                    }
                    cursor.close();
                    cursor = null;
                    for (int a = 0; a < contactsArray.size(); a++) {
                        TLRPC.Contact u = contactsArray.get(a);
                        if (bookContacts.indexOfKey(u.user_id) < 0) {
                            TLRPC.User user = getMessagesController().getUser(Integer.valueOf(u.user_id));
                            addContactToPhoneBook(user, false);
                        }
                    }
                }
                if (cursor == null) {
                    return;
                }
            } catch (Exception e) {
                FileLog.e(e);
                if (cursor == null) {
                    return;
                }
            }
            cursor.close();
        } catch (Throwable th) {
            if (cursor != null) {
                cursor.close();
            }
            throw th;
        }
    }

    private void performWriteContactsToPhoneBook() {
        final ArrayList<TLRPC.Contact> contactsArray = new ArrayList<>(this.contacts);
        Utilities.phoneBookQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ContactsController$0fNtFa1pwGE0ETZcbenRRvudD4k
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$performWriteContactsToPhoneBook$46$ContactsController(contactsArray);
            }
        });
    }

    private void applyContactsUpdates(ArrayList<Integer> ids, ConcurrentHashMap<Integer, TLRPC.User> userDict, ArrayList<TLRPC.Contact> newC, ArrayList<Integer> contactsTD) {
        ArrayList<TLRPC.Contact> newC2;
        ArrayList<Integer> contactsTD2;
        int i;
        boolean z;
        int index;
        int index2;
        if (newC == null || contactsTD == null) {
            newC2 = new ArrayList<>();
            contactsTD2 = new ArrayList<>();
            for (int a = 0; a < ids.size(); a++) {
                Integer uid = ids.get(a);
                if (uid.intValue() > 0) {
                    TLRPC.Contact contact = new TLRPC.Contact();
                    contact.user_id = uid.intValue();
                    newC2.add(contact);
                } else if (uid.intValue() < 0) {
                    contactsTD2.add(Integer.valueOf(-uid.intValue()));
                }
            }
        } else {
            newC2 = newC;
            contactsTD2 = contactsTD;
        }
        if (BuildVars.LOGS_ENABLED) {
            FileLog.d("process update - contacts add = " + newC2.size() + " delete = " + contactsTD2.size());
        }
        StringBuilder toAdd = new StringBuilder();
        StringBuilder toDelete = new StringBuilder();
        boolean reloadContacts = false;
        int a2 = 0;
        while (true) {
            i = -1;
            z = true;
            if (a2 >= newC2.size()) {
                break;
            }
            TLRPC.Contact newContact = newC2.get(a2);
            TLRPC.User user = null;
            if (userDict != null) {
                TLRPC.User user2 = userDict.get(Integer.valueOf(newContact.user_id));
                user = user2;
            }
            if (user == null) {
                user = getMessagesController().getUser(Integer.valueOf(newContact.user_id));
            } else {
                getMessagesController().putUser(user, true);
            }
            if (user == null || TextUtils.isEmpty(user.phone)) {
                reloadContacts = true;
            } else {
                Contact contact2 = this.contactsBookSPhones.get(user.phone);
                if (contact2 != null && (index2 = contact2.shortPhones.indexOf(user.phone)) != -1) {
                    contact2.phoneDeleted.set(index2, 0);
                }
                if (toAdd.length() != 0) {
                    toAdd.append(",");
                }
                toAdd.append(user.phone);
            }
            a2++;
        }
        int a3 = 0;
        while (a3 < contactsTD2.size()) {
            final Integer uid2 = contactsTD2.get(a3);
            Utilities.phoneBookQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ContactsController$fv20Y3IAOFsKFdIcLfFCj95ySK4
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$applyContactsUpdates$47$ContactsController(uid2);
                }
            });
            TLRPC.User user3 = null;
            if (userDict != null) {
                TLRPC.User user4 = userDict.get(uid2);
                user3 = user4;
            }
            if (user3 == null) {
                user3 = getMessagesController().getUser(uid2);
            } else {
                getMessagesController().putUser(user3, z);
            }
            if (user3 == null) {
                reloadContacts = true;
            } else if (!TextUtils.isEmpty(user3.phone)) {
                Contact contact3 = this.contactsBookSPhones.get(user3.phone);
                if (contact3 != null && (index = contact3.shortPhones.indexOf(user3.phone)) != i) {
                    contact3.phoneDeleted.set(index, 1);
                }
                if (toDelete.length() != 0) {
                    toDelete.append(",");
                }
                toDelete.append(user3.phone);
            }
            a3++;
            i = -1;
            z = true;
        }
        int a4 = toAdd.length();
        if (a4 != 0 || toDelete.length() != 0) {
            getMessagesStorage().applyPhoneBookUpdates(toAdd.toString(), toDelete.toString());
        }
        if (reloadContacts) {
            Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ContactsController$dWHAvGIt0pf7Bg2YwOCC0p5r9fk
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$applyContactsUpdates$48$ContactsController();
                }
            });
            return;
        }
        final ArrayList<TLRPC.Contact> newContacts = newC2;
        final ArrayList<Integer> contactsToDelete = contactsTD2;
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ContactsController$fnMcjut0_CrnNiKuNYJoEe5y3b8
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$applyContactsUpdates$49$ContactsController(newContacts, contactsToDelete);
            }
        });
    }

    public /* synthetic */ void lambda$applyContactsUpdates$47$ContactsController(Integer uid) {
        deleteContactFromPhoneBook(uid.intValue());
    }

    public /* synthetic */ void lambda$applyContactsUpdates$48$ContactsController() {
        loadContacts(false, 0);
    }

    public /* synthetic */ void lambda$applyContactsUpdates$49$ContactsController(ArrayList newContacts, ArrayList contactsToDelete) {
        for (int a = 0; a < newContacts.size(); a++) {
            TLRPC.Contact contact = (TLRPC.Contact) newContacts.get(a);
            if (this.contactsDict.get(Integer.valueOf(contact.user_id)) == null) {
                this.contacts.add(contact);
                this.contactsDict.put(Integer.valueOf(contact.user_id), contact);
            }
        }
        for (int a2 = 0; a2 < contactsToDelete.size(); a2++) {
            Integer uid = (Integer) contactsToDelete.get(a2);
            TLRPC.Contact contact2 = this.contactsDict.get(uid);
            if (contact2 != null) {
                this.contacts.remove(contact2);
                this.contactsDict.remove(uid);
            }
        }
        if (!newContacts.isEmpty()) {
            updateUnregisteredContacts();
            performWriteContactsToPhoneBook();
        }
        performSyncPhoneBook(getContactsCopy(this.contactsBook), false, false, false, false, true, false);
        buildContactsSectionsArrays(!newContacts.isEmpty());
        getNotificationCenter().postNotificationName(NotificationCenter.contactsDidLoad, new Object[0]);
    }

    public void processContactsUpdates(ArrayList<Integer> ids, ConcurrentHashMap<Integer, TLRPC.User> userDict) {
        int idx;
        int idx2;
        ArrayList<TLRPC.Contact> newContacts = new ArrayList<>();
        ArrayList<Integer> contactsToDelete = new ArrayList<>();
        for (Integer uid : ids) {
            if (uid.intValue() > 0) {
                TLRPC.Contact contact = new TLRPC.Contact();
                contact.user_id = uid.intValue();
                newContacts.add(contact);
                if (!this.delayedContactsUpdate.isEmpty() && (idx = this.delayedContactsUpdate.indexOf(Integer.valueOf(-uid.intValue()))) != -1) {
                    this.delayedContactsUpdate.remove(idx);
                }
            } else if (uid.intValue() < 0) {
                contactsToDelete.add(Integer.valueOf(-uid.intValue()));
                if (!this.delayedContactsUpdate.isEmpty() && (idx2 = this.delayedContactsUpdate.indexOf(Integer.valueOf(-uid.intValue()))) != -1) {
                    this.delayedContactsUpdate.remove(idx2);
                }
            }
        }
        contactsToDelete.isEmpty();
        if (!newContacts.isEmpty()) {
            getMessagesStorage().putContacts(newContacts, false);
        }
        if (!this.contactsLoaded || !this.contactsBookLoaded) {
            this.delayedContactsUpdate.addAll(ids);
            if (BuildVars.LOGS_ENABLED) {
                FileLog.d("delay update - contacts add = " + newContacts.size() + " delete = " + contactsToDelete.size());
                return;
            }
            return;
        }
        applyContactsUpdates(ids, userDict, newContacts, contactsToDelete);
    }

    public long addContactToPhoneBook(TLRPC.User user, boolean check) {
        String name;
        long res;
        if (this.systemAccount == null || user == null || !hasContactsPermission()) {
            return -1L;
        }
        long res2 = -1;
        synchronized (this.observerLock) {
            this.ignoreChanges = true;
        }
        ContentResolver contentResolver = ApplicationLoader.applicationContext.getContentResolver();
        if (check) {
            try {
                Uri rawContactUri = ContactsContract.RawContacts.CONTENT_URI.buildUpon().appendQueryParameter("caller_is_syncadapter", "true").appendQueryParameter("account_name", this.systemAccount.name).appendQueryParameter("account_type", this.systemAccount.type).build();
                contentResolver.delete(rawContactUri, "sync2 = " + user.id, null);
            } catch (Exception e) {
            }
        }
        ArrayList<ContentProviderOperation> query = new ArrayList<>();
        ContentProviderOperation.Builder builder = ContentProviderOperation.newInsert(ContactsContract.RawContacts.CONTENT_URI);
        builder.withValue("account_name", this.systemAccount.name);
        builder.withValue("account_type", this.systemAccount.type);
        builder.withValue("sync1", TextUtils.isEmpty(user.phone) ? "" : user.phone);
        builder.withValue("sync2", Integer.valueOf(user.id));
        query.add(builder.build());
        ContentProviderOperation.Builder builder2 = ContentProviderOperation.newInsert(ContactsContract.Data.CONTENT_URI);
        builder2.withValueBackReference("raw_contact_id", 0);
        builder2.withValue("mimetype", "vnd.android.cursor.item/name");
        builder2.withValue("data2", user.first_name);
        builder2.withValue("data3", user.last_name);
        query.add(builder2.build());
        ContentProviderOperation.Builder builder3 = ContentProviderOperation.newInsert(ContactsContract.Data.CONTENT_URI);
        builder3.withValueBackReference("raw_contact_id", 0);
        builder3.withValue("mimetype", "vnd.android.cursor.item/vnd.im.uwrkaxlmjj.messenger.android.profile");
        builder3.withValue("data1", Integer.valueOf(user.id));
        builder3.withValue("data2", LocaleController.getString(mpEIGo.juqQQs.esbSDO.R.string.AppName) + " Profile");
        if (TextUtils.isEmpty(user.phone)) {
            name = formatName(user.first_name, user.last_name);
        } else {
            name = Marker.ANY_NON_NULL_MARKER + user.phone;
        }
        builder3.withValue("data3", name);
        builder3.withValue("data4", Integer.valueOf(user.id));
        query.add(builder3.build());
        try {
            ContentProviderResult[] result = contentResolver.applyBatch("com.android.contacts", query);
            if (result != null && result.length > 0 && result[0].uri != null) {
                res2 = Long.parseLong(result[0].uri.getLastPathSegment());
            }
            res = res2;
        } catch (Exception e2) {
            res = -1;
        }
        synchronized (this.observerLock) {
            this.ignoreChanges = false;
        }
        return res;
    }

    private void deleteContactFromPhoneBook(int uid) {
        if (!hasContactsPermission()) {
            return;
        }
        synchronized (this.observerLock) {
            this.ignoreChanges = true;
        }
        try {
            ContentResolver contentResolver = ApplicationLoader.applicationContext.getContentResolver();
            Uri rawContactUri = ContactsContract.RawContacts.CONTENT_URI.buildUpon().appendQueryParameter("caller_is_syncadapter", "true").appendQueryParameter("account_name", this.systemAccount.name).appendQueryParameter("account_type", this.systemAccount.type).build();
            contentResolver.delete(rawContactUri, "sync2 = " + uid, null);
        } catch (Exception e) {
            FileLog.e(e);
        }
        synchronized (this.observerLock) {
            this.ignoreChanges = false;
        }
    }

    protected void markAsContacted(final String contactId) {
        if (contactId == null) {
            return;
        }
        Utilities.phoneBookQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ContactsController$51hFG-yDYyW8sjzp9dgAIS2mPvc
            @Override // java.lang.Runnable
            public final void run() {
                ContactsController.lambda$markAsContacted$50(contactId);
            }
        });
    }

    static /* synthetic */ void lambda$markAsContacted$50(String contactId) {
        Uri uri = Uri.parse(contactId);
        ContentValues values = new ContentValues();
        values.put("last_time_contacted", Long.valueOf(System.currentTimeMillis()));
        ContentResolver cr = ApplicationLoader.applicationContext.getContentResolver();
        cr.update(uri, values, null, null);
    }

    public void addContact(final TLRPC.User user, boolean exception) {
        if (user == null) {
            return;
        }
        TLRPC.TL_contacts_addContact req = new TLRPC.TL_contacts_addContact();
        req.id = getMessagesController().getInputUser(user);
        req.first_name = user.first_name;
        req.last_name = user.last_name;
        req.phone = user.phone;
        req.add_phone_privacy_exception = exception;
        if (req.phone == null) {
            req.phone = "";
        } else if (req.phone.length() > 0 && !req.phone.startsWith(Marker.ANY_NON_NULL_MARKER)) {
            req.phone = Marker.ANY_NON_NULL_MARKER + req.phone;
        }
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ContactsController$YY9rvHI5-20spK2jwtjeD_ICt5o
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) throws Exception {
                this.f$0.lambda$addContact$53$ContactsController(user, tLObject, tL_error);
            }
        }, 6);
    }

    public /* synthetic */ void lambda$addContact$53$ContactsController(TLRPC.User user, TLObject response, TLRPC.TL_error error) throws Exception {
        int index;
        if (error != null) {
            return;
        }
        final TLRPC.Updates res = (TLRPC.Updates) response;
        getMessagesController().processUpdates(res, false);
        for (int a = 0; a < res.users.size(); a++) {
            final TLRPC.User u = res.users.get(a);
            if (u.id == user.id) {
                Utilities.phoneBookQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ContactsController$YJntOTniBUQgD1F1qjBi4bvvbG8
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$51$ContactsController(u);
                    }
                });
                TLRPC.Contact newContact = new TLRPC.Contact();
                newContact.user_id = u.id;
                ArrayList<TLRPC.Contact> arrayList = new ArrayList<>();
                arrayList.add(newContact);
                getMessagesStorage().putContacts(arrayList, false);
                if (!TextUtils.isEmpty(u.phone)) {
                    formatName(u.first_name, u.last_name);
                    getMessagesStorage().applyPhoneBookUpdates(u.phone, "");
                    Contact contact = this.contactsBookSPhones.get(u.phone);
                    if (contact != null && (index = contact.shortPhones.indexOf(u.phone)) != -1) {
                        contact.phoneDeleted.set(index, 0);
                    }
                }
            }
        }
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ContactsController$e8EvxLdHwDKySQ0oCSj4Kv772R8
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$52$ContactsController(res);
            }
        });
    }

    public /* synthetic */ void lambda$null$51$ContactsController(TLRPC.User u) {
        addContactToPhoneBook(u, true);
    }

    public /* synthetic */ void lambda$null$52$ContactsController(TLRPC.Updates res) {
        for (int a = 0; a < res.users.size(); a++) {
            TLRPC.User u = res.users.get(a);
            if (u.contact && this.contactsDict.get(Integer.valueOf(u.id)) == null) {
                TLRPC.Contact newContact = new TLRPC.Contact();
                newContact.user_id = u.id;
                this.contacts.add(newContact);
                this.contactsDict.put(Integer.valueOf(newContact.user_id), newContact);
            }
        }
        buildContactsSectionsArrays(true);
        getNotificationCenter().postNotificationName(NotificationCenter.contactsDidLoad, new Object[0]);
    }

    public void deleteContact(final ArrayList<TLRPC.User> users) {
        if (users == null || users.isEmpty()) {
            return;
        }
        TLRPC.TL_contacts_deleteContacts req = new TLRPC.TL_contacts_deleteContacts();
        final ArrayList<Integer> uids = new ArrayList<>();
        for (TLRPC.User user : users) {
            TLRPC.InputUser inputUser = getMessagesController().getInputUser(user);
            if (inputUser != null) {
                user.contact = false;
                uids.add(Integer.valueOf(user.id));
                req.id.add(inputUser);
            }
        }
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ContactsController$n0XOp-n9LP57bUUW68bEdlSrt4w
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) throws Exception {
                this.f$0.lambda$deleteContact$56$ContactsController(uids, users, tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$deleteContact$56$ContactsController(ArrayList uids, final ArrayList users, TLObject response, TLRPC.TL_error error) throws Exception {
        int index;
        if (error != null) {
            return;
        }
        getMessagesController().processUpdates((TLRPC.Updates) response, false);
        getMessagesStorage().deleteContacts(uids);
        Utilities.phoneBookQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ContactsController$Z5xNTrXwJuJ7o1J6vbr8gHs4VkA
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$54$ContactsController(users);
            }
        });
        for (int a = 0; a < users.size(); a++) {
            TLRPC.User user = (TLRPC.User) users.get(a);
            if (!TextUtils.isEmpty(user.phone)) {
                getMessagesStorage().applyPhoneBookUpdates(user.phone, "");
                Contact contact = this.contactsBookSPhones.get(user.phone);
                if (contact != null && (index = contact.shortPhones.indexOf(user.phone)) != -1) {
                    contact.phoneDeleted.set(index, 1);
                }
            }
        }
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ContactsController$FhzZlYmIVtsRZihKldyJm5-yoaQ
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$55$ContactsController(users);
            }
        });
    }

    public /* synthetic */ void lambda$null$54$ContactsController(ArrayList users) {
        Iterator it = users.iterator();
        while (it.hasNext()) {
            TLRPC.User user = (TLRPC.User) it.next();
            deleteContactFromPhoneBook(user.id);
        }
    }

    public /* synthetic */ void lambda$null$55$ContactsController(ArrayList users) {
        boolean remove = false;
        Iterator it = users.iterator();
        while (it.hasNext()) {
            TLRPC.User user = (TLRPC.User) it.next();
            TLRPC.Contact contact = this.contactsDict.get(Integer.valueOf(user.id));
            if (contact != null) {
                remove = true;
                this.contacts.remove(contact);
                this.contactsDict.remove(Integer.valueOf(user.id));
            }
        }
        if (remove) {
            buildContactsSectionsArrays(false);
        }
        getNotificationCenter().postNotificationName(NotificationCenter.updateInterfaces, 1);
        getNotificationCenter().postNotificationName(NotificationCenter.contactsDidLoad, new Object[0]);
    }

    public void reloadContactsStatuses() {
        saveContactsLoadTime();
        getMessagesController().clearFullUsers();
        SharedPreferences preferences = MessagesController.getMainSettings(this.currentAccount);
        final SharedPreferences.Editor editor = preferences.edit();
        editor.putBoolean("needGetStatuses", true).commit();
        TLRPC.TL_contacts_getStatuses req = new TLRPC.TL_contacts_getStatuses();
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ContactsController$ujVUWomflgRV7BDvfjaw15ALeGU
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$reloadContactsStatuses$58$ContactsController(editor, tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$reloadContactsStatuses$58$ContactsController(final SharedPreferences.Editor editor, final TLObject response, TLRPC.TL_error error) {
        if (error == null) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ContactsController$hlg99V0y89dwspbzonBZsql1YEU
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$57$ContactsController(editor, response);
                }
            });
        }
    }

    public /* synthetic */ void lambda$null$57$ContactsController(SharedPreferences.Editor editor, TLObject response) {
        editor.remove("needGetStatuses").commit();
        TLRPC.Vector vector = (TLRPC.Vector) response;
        if (!vector.objects.isEmpty()) {
            ArrayList<TLRPC.User> dbUsersStatus = new ArrayList<>();
            for (Object object : vector.objects) {
                TLRPC.User toDbUser = new TLRPC.TL_user();
                TLRPC.TL_contactStatus status = (TLRPC.TL_contactStatus) object;
                if (status != null) {
                    if (status.status instanceof TLRPC.TL_userStatusRecently) {
                        status.status.expires = -100;
                    } else if (status.status instanceof TLRPC.TL_userStatusLastWeek) {
                        status.status.expires = -101;
                    } else if (status.status instanceof TLRPC.TL_userStatusLastMonth) {
                        status.status.expires = ScreenAudioCapturer.ERROR_AUDIO_RECORD_INIT_EXCEPTION;
                    }
                    TLRPC.User user = getMessagesController().getUser(Integer.valueOf(status.user_id));
                    if (user != null) {
                        user.status = status.status;
                    }
                    toDbUser.status = status.status;
                    dbUsersStatus.add(toDbUser);
                }
            }
            getMessagesStorage().updateUsers(dbUsersStatus, true, true, true);
        }
        getNotificationCenter().postNotificationName(NotificationCenter.updateInterfaces, 4);
    }

    public void loadPrivacySettings() {
        if (this.loadingDeleteInfo == 0) {
            this.loadingDeleteInfo = 1;
            getConnectionsManager().sendRequest(new TLRPC.TL_account_getAccountTTL(), new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ContactsController$3m7_kpeFuH_qai38F65SP1dHTmg
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$loadPrivacySettings$60$ContactsController(tLObject, tL_error);
                }
            });
        }
        int a = 0;
        while (true) {
            int[] iArr = this.loadingPrivacyInfo;
            if (a < iArr.length) {
                if (iArr[a] == 0) {
                    iArr[a] = 1;
                    final int num = a;
                    TLRPC.TL_account_getPrivacy req = new TLRPC.TL_account_getPrivacy();
                    switch (num) {
                        case 0:
                            req.key = new TLRPC.TL_inputPrivacyKeyStatusTimestamp();
                            break;
                        case 1:
                            req.key = new TLRPC.TL_inputPrivacyKeyChatInvite();
                            break;
                        case 2:
                            req.key = new TLRPC.TL_inputPrivacyKeyPhoneCall();
                            break;
                        case 3:
                            req.key = new TLRPC.TL_inputPrivacyKeyPhoneP2P();
                            break;
                        case 4:
                            req.key = new TLRPC.TL_inputPrivacyKeyProfilePhoto();
                            break;
                        case 5:
                            req.key = new TLRPC.TL_inputPrivacyKeyForwards();
                            break;
                        case 6:
                            req.key = new TLRPC.TL_inputPrivacyKeyPhoneNumber();
                            break;
                        case 7:
                        default:
                            req.key = new TLRPC.TL_inputPrivacyKeyAddedByPhone();
                            break;
                        case 8:
                            req.key = new TLRPC.TL_inputPrivacyKeyMoment();
                            break;
                    }
                    getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ContactsController$THMRhKNZQs7hY8TW3cfKsR66950
                        @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                        public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                            this.f$0.lambda$loadPrivacySettings$62$ContactsController(num, tLObject, tL_error);
                        }
                    });
                }
                a++;
            } else {
                getNotificationCenter().postNotificationName(NotificationCenter.privacyRulesUpdated, new Object[0]);
                return;
            }
        }
    }

    public /* synthetic */ void lambda$loadPrivacySettings$60$ContactsController(final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ContactsController$pgLpYWWpkKOTEqv4ruo3IjKsg0g
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$59$ContactsController(error, response);
            }
        });
    }

    public /* synthetic */ void lambda$null$59$ContactsController(TLRPC.TL_error error, TLObject response) {
        if (error == null) {
            TLRPC.TL_accountDaysTTL ttl = (TLRPC.TL_accountDaysTTL) response;
            this.deleteAccountTTL = ttl.days;
            this.loadingDeleteInfo = 2;
        } else {
            this.loadingDeleteInfo = 0;
        }
        getNotificationCenter().postNotificationName(NotificationCenter.privacyRulesUpdated, new Object[0]);
    }

    public /* synthetic */ void lambda$loadPrivacySettings$62$ContactsController(final int num, final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$ContactsController$aEkPmphTcicnDQb58V9tlCaqVdc
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$61$ContactsController(error, response, num);
            }
        });
    }

    public /* synthetic */ void lambda$null$61$ContactsController(TLRPC.TL_error error, TLObject response, int num) {
        if (error != null) {
            this.loadingPrivacyInfo[num] = 0;
        } else {
            TLRPC.TL_account_privacyRules rules = (TLRPC.TL_account_privacyRules) response;
            getMessagesController().putUsers(rules.users, false);
            getMessagesController().putChats(rules.chats, false);
            switch (num) {
                case 0:
                    this.lastseenPrivacyRules = rules.rules;
                    break;
                case 1:
                    this.groupPrivacyRules = rules.rules;
                    break;
                case 2:
                    this.callPrivacyRules = rules.rules;
                    break;
                case 3:
                    this.p2pPrivacyRules = rules.rules;
                    break;
                case 4:
                    this.profilePhotoPrivacyRules = rules.rules;
                    break;
                case 5:
                    this.forwardsPrivacyRules = rules.rules;
                    break;
                case 6:
                    this.phonePrivacyRules = rules.rules;
                    break;
                case 7:
                default:
                    this.addedByPhonePrivacyRules = rules.rules;
                    break;
                case 8:
                    this.momentPrivacyRules = rules.rules;
                    break;
            }
            this.loadingPrivacyInfo[num] = 2;
        }
        getNotificationCenter().postNotificationName(NotificationCenter.privacyRulesUpdated, new Object[0]);
    }

    public void setDeleteAccountTTL(int ttl) {
        this.deleteAccountTTL = ttl;
    }

    public int getDeleteAccountTTL() {
        return this.deleteAccountTTL;
    }

    public boolean getLoadingDeleteInfo() {
        return this.loadingDeleteInfo != 2;
    }

    public boolean getLoadingPrivicyInfo(int type) {
        return this.loadingPrivacyInfo[type] != 2;
    }

    public ArrayList<TLRPC.PrivacyRule> getPrivacyRules(int type) {
        switch (type) {
            case 0:
                return this.lastseenPrivacyRules;
            case 1:
                return this.groupPrivacyRules;
            case 2:
                return this.callPrivacyRules;
            case 3:
                return this.p2pPrivacyRules;
            case 4:
                return this.profilePhotoPrivacyRules;
            case 5:
                return this.forwardsPrivacyRules;
            case 6:
                return this.phonePrivacyRules;
            case 7:
                return this.addedByPhonePrivacyRules;
            case 8:
                return this.momentPrivacyRules;
            default:
                return null;
        }
    }

    public void setPrivacyRules(ArrayList<TLRPC.PrivacyRule> rules, int type) {
        switch (type) {
            case 0:
                this.lastseenPrivacyRules = rules;
                break;
            case 1:
                this.groupPrivacyRules = rules;
                break;
            case 2:
                this.callPrivacyRules = rules;
                break;
            case 3:
                this.p2pPrivacyRules = rules;
                break;
            case 4:
                this.profilePhotoPrivacyRules = rules;
                break;
            case 5:
                this.forwardsPrivacyRules = rules;
                break;
            case 6:
                this.phonePrivacyRules = rules;
                break;
            case 7:
                this.addedByPhonePrivacyRules = rules;
                break;
            case 8:
                this.momentPrivacyRules = rules;
                break;
        }
        getNotificationCenter().postNotificationName(NotificationCenter.privacyRulesUpdated, new Object[0]);
        reloadContactsStatuses();
    }

    /* JADX WARN: Removed duplicated region for block: B:26:0x01da A[Catch: Exception -> 0x028e, TRY_LEAVE, TryCatch #0 {Exception -> 0x028e, blocks: (B:23:0x01c4, B:26:0x01da), top: B:43:0x011a }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void createOrUpdateConnectionServiceContact(int r27, java.lang.String r28, java.lang.String r29) {
        /*
            Method dump skipped, instruction units count: 670
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.ContactsController.createOrUpdateConnectionServiceContact(int, java.lang.String, java.lang.String):void");
    }

    public void deleteConnectionServiceContact() {
        if (!hasContactsPermission()) {
            return;
        }
        try {
            ContentResolver resolver = ApplicationLoader.applicationContext.getContentResolver();
            Cursor cursor = resolver.query(ContactsContract.Groups.CONTENT_URI, new String[]{"_id"}, "title=? AND account_type=? AND account_name=?", new String[]{"AppConnectionService", this.systemAccount.type, this.systemAccount.name}, null);
            if (cursor != null && cursor.moveToFirst()) {
                int groupID = cursor.getInt(0);
                cursor.close();
                Cursor cursor2 = resolver.query(ContactsContract.Data.CONTENT_URI, new String[]{"raw_contact_id"}, "mimetype=? AND data1=?", new String[]{"vnd.android.cursor.item/group_membership", groupID + ""}, null);
                if (cursor2 != null && cursor2.moveToFirst()) {
                    int contactID = cursor2.getInt(0);
                    cursor2.close();
                    resolver.delete(ContactsContract.RawContacts.CONTENT_URI, "_id=?", new String[]{contactID + ""});
                    return;
                }
                if (cursor2 != null) {
                    cursor2.close();
                    return;
                }
                return;
            }
            if (cursor != null) {
                cursor.close();
            }
        } catch (Exception x) {
            FileLog.e(x);
        }
    }

    public static String formatName(String firstName, String lastName) {
        if (!TextUtils.isEmpty(firstName)) {
            return firstName.trim();
        }
        return LocaleController.getString("UnKnown", mpEIGo.juqQQs.esbSDO.R.string.UnKnown);
    }
}
