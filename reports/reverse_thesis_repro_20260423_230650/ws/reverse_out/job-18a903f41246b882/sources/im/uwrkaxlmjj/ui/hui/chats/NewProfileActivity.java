package im.uwrkaxlmjj.ui.hui.chats;

import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.text.TextUtils;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.core.content.ContextCompat;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import butterknife.BindView;
import butterknife.OnClick;
import com.bjz.comm.net.utils.HttpUtils;
import com.google.android.exoplayer2.trackselection.AdaptiveTrackSelection;
import com.king.zxing.util.LogUtils;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.ContactsController;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MediaDataController;
import im.uwrkaxlmjj.messenger.MessageObject;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.MessagesStorage;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.NotificationsController;
import im.uwrkaxlmjj.messenger.SecretChatHelper;
import im.uwrkaxlmjj.messenger.SendMessagesHelper;
import im.uwrkaxlmjj.messenger.UserObject;
import im.uwrkaxlmjj.messenger.Utilities;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.tgnet.TLRPCContacts;
import im.uwrkaxlmjj.ui.ChatActivity;
import im.uwrkaxlmjj.ui.CommonGroupsActivity;
import im.uwrkaxlmjj.ui.IdenticonActivity;
import im.uwrkaxlmjj.ui.MediaActivity;
import im.uwrkaxlmjj.ui.PhotoViewer;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenu;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.actionbar.XAlertDialog;
import im.uwrkaxlmjj.ui.cells.ShadowSectionCell;
import im.uwrkaxlmjj.ui.components.AlertsCreator;
import im.uwrkaxlmjj.ui.components.AvatarDrawable;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.components.IdenticonDrawable;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.dialogs.DialogCommonList;
import im.uwrkaxlmjj.ui.hcells.MryTextCheckCell;
import im.uwrkaxlmjj.ui.hcells.PhotoCell;
import im.uwrkaxlmjj.ui.hcells.TextSettingCell;
import im.uwrkaxlmjj.ui.hui.contacts.AddContactsInfoActivity;
import im.uwrkaxlmjj.ui.hui.contacts.ContactsUtils;
import im.uwrkaxlmjj.ui.hui.contacts.GreetEditActivity;
import im.uwrkaxlmjj.ui.hui.contacts.NoteAndGroupingEditActivity;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.FcPageMineActivity;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.FcPageOthersActivity;
import im.uwrkaxlmjj.ui.hui.visualcall.VisualCallActivity;
import im.uwrkaxlmjj.ui.hviews.MryRoundButton;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import im.uwrkaxlmjj.ui.hviews.dialogs.XDialog;
import java.util.ArrayList;
import java.util.List;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class NewProfileActivity extends BaseFragment implements NotificationCenter.NotificationCenterDelegate {
    private int addContactsEmptyRow;
    private int addContactsRow;
    private ArrayList<String> albumUrls;
    private int appCodeRow;
    private int audioRow;
    private int blockRow;
    private boolean creatingChat;
    private TLRPC.EncryptedChat currentEncryptedChat;
    private int deleteContactRow;
    private long dialog_id;
    boolean enableFriendMoment;
    private int encriptEmptyRow;
    private int encriptRow;
    private int filesRow;
    private boolean forbidAddContact;
    private int fromType;
    private int groupRow;
    private int groupingAndRemarksRow;
    private boolean hasAdminRights;
    private int headerEmptyRow;
    private int headerRow;
    private int hubEmptyRow;
    private int hubRow;
    private boolean isBot;
    private int[] lastMediaCount;
    private int linksRow;

    @BindView(R.attr.listview)
    RecyclerListView listView;
    private MyAdapter mAdapter;
    private Context mContext;

    @BindView(R.attr.ll_bottom_btn)
    LinearLayout mLlBottomBtn;
    private MediaActivity mediaActivity;
    private int[] mediaCount;
    private int moreInfoRow;
    private int notifyRow;
    private Runnable parseUserFriendAlbumRunnable;
    private boolean parseUserFriendAlbumRunnableIsRunning;
    private int phoneRow;
    private int photosRow;
    private int[] prevMediaCount;
    private boolean reportSpam;
    private int rowCount;
    private int sendToSelfEmptyRow;
    private int sendToSelfRow;
    private MediaActivity.SharedMediaData[] sharedMediaData;
    private int signEmptyRow;
    private int signRow;

    @BindView(R.attr.tv_add_friend)
    TextView tvAddFriend;

    @BindView(R.attr.tv_secret_chat)
    TextView tvSecretChat;

    @BindView(R.attr.tv_send_message)
    TextView tvSendMessage;
    private TLRPC.User user;
    private boolean userBlocked;
    private int userGroupId;
    private TLRPCContacts.CL_userFull_v1 userInfo;
    private String userNote;
    private int user_id;
    private int voiceRow;

    public NewProfileActivity(Bundle args) {
        super(args);
        this.userNote = "";
        this.enableFriendMoment = false;
        this.lastMediaCount = new int[]{-1, -1, -1, -1, -1};
        this.mediaCount = new int[]{-1, -1, -1, -1, -1};
        this.prevMediaCount = new int[]{-1, -1, -1, -1, -1};
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        if (this.arguments != null) {
            this.user_id = this.arguments.getInt("user_id", 0);
            this.forbidAddContact = this.arguments.getBoolean("forbid_add_contact", false);
            this.hasAdminRights = this.arguments.getBoolean("has_admin_right", false);
            this.reportSpam = this.arguments.getBoolean("reportSpam", false);
            this.fromType = this.arguments.getInt("from_type", 0);
            if (this.user_id == 0) {
                return false;
            }
            this.dialog_id = this.arguments.getLong("dialog_id", 0L);
            TLRPC.User user = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(this.user_id));
            this.user = user;
            if (user == null) {
                return false;
            }
            if (this.dialog_id != 0) {
                this.currentEncryptedChat = MessagesController.getInstance(this.currentAccount).getEncryptedChat(Integer.valueOf((int) (this.dialog_id >> 32)));
            }
            NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.updateInterfaces);
            NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.contactsDidLoad);
            NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.encryptedChatCreated);
            NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.encryptedChatUpdated);
            NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.blockedUsersDidLoad);
            NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.botInfoDidLoad);
            NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.userFullInfoDidLoad);
            this.userBlocked = MessagesController.getInstance(this.currentAccount).blockedUsers.indexOfKey(this.user_id) >= 0;
            if (this.user.bot) {
                this.isBot = true;
                MediaDataController.getInstance(this.currentAccount).loadBotInfo(this.user.id, true, this.classGuid);
            }
            TLRPC.UserFull full = MessagesController.getInstance(this.currentAccount).getUserFull(this.user_id);
            if (full instanceof TLRPCContacts.CL_userFull_v1) {
                this.userInfo = (TLRPCContacts.CL_userFull_v1) full;
            }
            MessagesController.getInstance(this.currentAccount).loadFullUser(this.user_id, this.classGuid, true);
        }
        this.sharedMediaData = new MediaActivity.SharedMediaData[5];
        int a = 0;
        while (true) {
            MediaActivity.SharedMediaData[] sharedMediaDataArr = this.sharedMediaData;
            if (a < sharedMediaDataArr.length) {
                sharedMediaDataArr[a] = new MediaActivity.SharedMediaData();
                this.sharedMediaData[a].setMaxId(0, this.dialog_id != 0 ? Integer.MIN_VALUE : Integer.MAX_VALUE);
                a++;
            } else {
                int a2 = this.currentAccount;
                NotificationCenter.getInstance(a2).addObserver(this, NotificationCenter.mediaCountDidLoad);
                NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.mediaCountsDidLoad);
                NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.mediaDidLoad);
                NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.updateInterfaces);
                NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.didReceiveNewMessages);
                NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.messagesDeleted);
                NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.closeChats);
                NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.groupingChanged);
                return true;
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.mContext = context;
        this.fragmentView = LayoutInflater.from(context).inflate(R.layout.activity_new_profile, (ViewGroup) null);
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        useButterKnife();
        initActionBar();
        initView();
        updateRow();
        return this.fragmentView;
    }

    private void initActionBar() {
        this.actionBar.setCastShadows(false);
        this.actionBar.setTitle(LocaleController.getString("PersonalInfo", R.string.PersonalInfo));
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.hui.chats.NewProfileActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    NewProfileActivity.this.finishFragment();
                } else if (id == 0) {
                    Bundle args = new Bundle();
                    args.putInt("user_id", NewProfileActivity.this.user_id);
                    NewProfileActivity.this.presentFragmentFromBottom(new UserProfileShareStepOneActivity(args), false, false);
                }
            }
        });
        if (this.user_id != 777000 && this.user.mutual_contact) {
            ActionBarMenu menuView = this.actionBar.createMenu();
            menuView.addItem(0, R.drawable.msg_shareout);
        }
    }

    private void initView() {
        this.listView.setLayoutManager(new LinearLayoutManager(this.mContext));
        RecyclerListView recyclerListView = this.listView;
        MyAdapter myAdapter = new MyAdapter();
        this.mAdapter = myAdapter;
        recyclerListView.setAdapter(myAdapter);
        this.listView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.hui.chats.-$$Lambda$NewProfileActivity$Vm_jlGE8J28-ZEEpi7fN6ByYxkQ
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public final void onItemClick(View view, int i) {
                this.f$0.lambda$initView$2$NewProfileActivity(view, i);
            }
        });
        this.mLlBottomBtn.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
        this.tvAddFriend.setTextColor(Theme.getColor(Theme.key_actionBarDefault));
        this.tvSendMessage.setTextColor(Theme.getColor(Theme.key_actionBarDefault));
        this.tvSecretChat.setTextColor(Theme.getColor(Theme.key_actionBarDefault));
        this.tvSecretChat.setText(LocaleController.getString("chat_encrypt", R.string.chat_encrypt));
        this.tvAddFriend.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_bottomBarSelectedColor)));
        this.tvAddFriend.setText(LocaleController.getString("chat_add_contacts", R.string.chat_add_contacts));
        this.tvSendMessage.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_bottomBarSelectedColor)));
        this.tvSendMessage.setText(LocaleController.getString("chat_send_messages", R.string.chat_send_messages));
        this.tvSecretChat.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_bottomBarSelectedColor)));
    }

    public /* synthetic */ void lambda$initView$2$NewProfileActivity(View view, int position) {
        int tab;
        long did;
        long flags;
        if (getParentActivity() == null) {
            return;
        }
        if (position == this.groupRow) {
            presentFragment(new CommonGroupsActivity(this.user_id));
            return;
        }
        if (position != this.notifyRow) {
            if (position == this.blockRow) {
                TLRPC.User user = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(this.user_id));
                if (user == null) {
                    return;
                }
                if (!this.isBot || MessagesController.isSupportUser(user)) {
                    if (this.userBlocked) {
                        MessagesController.getInstance(this.currentAccount).unblockUser(this.user_id);
                        AlertsCreator.showSimpleToast(this, LocaleController.getString("UserUnBlacklisted", R.string.UserUnBlacklisted));
                        return;
                    } else {
                        if (this.reportSpam) {
                            AlertsCreator.showBlockReportSpamAlert(this, this.user_id, user, null, this.currentEncryptedChat, false, null, new MessagesStorage.IntCallback() { // from class: im.uwrkaxlmjj.ui.hui.chats.-$$Lambda$NewProfileActivity$N-ls8fU0VR4iHJFA094DQ9I2hW8
                                @Override // im.uwrkaxlmjj.messenger.MessagesStorage.IntCallback
                                public final void run(int i) {
                                    this.f$0.lambda$null$0$NewProfileActivity(i);
                                }
                            });
                            return;
                        }
                        List<String> arrList = new ArrayList<>();
                        arrList.add(LocaleController.formatString("AreYouSureBlockContact3", R.string.AreYouSureBlockContact3, ContactsController.formatName(user.first_name, user.last_name)));
                        arrList.add(LocaleController.getString("OK", R.string.OK));
                        int[] iTextColor = {-7631463, -570319};
                        DialogCommonList dialogCommonList = new DialogCommonList(getParentActivity(), arrList, (List<Integer>) null, iTextColor, new DialogCommonList.RecyclerviewItemClickCallBack() { // from class: im.uwrkaxlmjj.ui.hui.chats.-$$Lambda$NewProfileActivity$6eXraXtLPKXFTXFJng7sI0BCEzA
                            @Override // im.uwrkaxlmjj.ui.dialogs.DialogCommonList.RecyclerviewItemClickCallBack
                            public final void onRecyclerviewItemClick(int i) {
                                this.f$0.lambda$null$1$NewProfileActivity(i);
                            }
                        }, 1);
                        dialogCommonList.setCancle(Color.parseColor("#222222"), 16);
                        dialogCommonList.show();
                        return;
                    }
                }
                if (!this.userBlocked) {
                    MessagesController.getInstance(this.currentAccount).blockUser(this.user_id);
                    return;
                }
                MessagesController.getInstance(this.currentAccount).unblockUser(this.user_id);
                SendMessagesHelper.getInstance(this.currentAccount).sendMessage("/start", this.user_id, null, null, false, null, null, null, true, 0);
                finishFragment();
                return;
            }
            if (position == this.photosRow || position == this.filesRow || position == this.linksRow || position == this.audioRow || position == this.voiceRow) {
                if (position == this.photosRow) {
                    tab = 0;
                } else {
                    int tab2 = this.filesRow;
                    if (position == tab2) {
                        tab = 1;
                    } else {
                        int tab3 = this.linksRow;
                        if (position == tab3) {
                            tab = 3;
                        } else {
                            int tab4 = this.audioRow;
                            if (position == tab4) {
                                tab = 4;
                            } else {
                                tab = 2;
                            }
                        }
                    }
                }
                Bundle args = new Bundle();
                int i = this.user_id;
                if (i != 0) {
                    long j = this.dialog_id;
                    if (j == 0) {
                        j = i;
                    }
                    args.putLong("dialog_id", j);
                }
                int[] media = new int[5];
                System.arraycopy(this.lastMediaCount, 0, media, 0, media.length);
                MediaActivity mediaActivity = new MediaActivity(args, media, this.sharedMediaData, tab);
                this.mediaActivity = mediaActivity;
                presentFragment(mediaActivity);
                return;
            }
            if (position == this.hubRow) {
                if (this.user == null && this.user_id == 0) {
                    return;
                }
                if (this.user_id == getUserConfig().getClientUserId()) {
                    presentFragment(new FcPageMineActivity());
                    return;
                } else {
                    presentFragment(new FcPageOthersActivity(this.user_id, this.user.access_hash));
                    return;
                }
            }
            if (position == this.encriptRow) {
                TLRPC.EncryptedChat encryptedChat = MessagesController.getInstance(this.currentAccount).getEncryptedChat(Integer.valueOf((int) (this.dialog_id >> 32)));
                if (encryptedChat instanceof TLRPC.TL_encryptedChat) {
                    Bundle args2 = new Bundle();
                    args2.putInt("chat_id", (int) (this.dialog_id >> 32));
                    presentFragment(new IdenticonActivity(args2));
                    return;
                }
                return;
            }
            if (position == this.groupingAndRemarksRow) {
                TLRPCContacts.CL_userFull_v1 cL_userFull_v1 = this.userInfo;
                if (cL_userFull_v1 == null || cL_userFull_v1.getExtendBean() == null) {
                    return;
                }
                Bundle bundle = new Bundle();
                bundle.putInt("user_id", this.user_id);
                bundle.putInt("groupId", this.userInfo.getExtendBean().group_id);
                bundle.putString("groupName", this.userInfo.getExtendBean().group_name);
                bundle.putInt("type", 2);
                presentFragment(new NoteAndGroupingEditActivity(bundle));
                return;
            }
            if (position != this.moreInfoRow) {
                if (position == this.deleteContactRow) {
                    deleteContact();
                    return;
                } else if (position == this.sendToSelfRow) {
                    sendMessage();
                    return;
                } else {
                    if (position == this.addContactsRow) {
                        jumpToEditGreetActivity();
                        return;
                    }
                    return;
                }
            }
            MoreUserInfoActivity fragment = new MoreUserInfoActivity(this.user_id, this.dialog_id, this.lastMediaCount);
            TLRPCContacts.CL_userFull_v1 cL_userFull_v12 = this.userInfo;
            if (cL_userFull_v12 != null) {
                fragment.setUserInfo(cL_userFull_v12);
            }
            presentFragment(fragment);
            return;
        }
        if (this.dialog_id != 0) {
            did = this.dialog_id;
        } else {
            did = this.user_id;
        }
        MryTextCheckCell checkCell = (MryTextCheckCell) view;
        boolean checked = true ^ checkCell.isChecked();
        boolean defaultEnabled = NotificationsController.getInstance(this.currentAccount).isGlobalNotificationsEnabled(did);
        if (checked) {
            SharedPreferences preferences = MessagesController.getNotificationsSettings(this.currentAccount);
            SharedPreferences.Editor editor = preferences.edit();
            if (defaultEnabled) {
                editor.remove("notify2_" + did);
            } else {
                editor.putInt("notify2_" + did, 0);
            }
            MessagesStorage.getInstance(this.currentAccount).setDialogFlags(did, 0L);
            editor.commit();
            TLRPC.Dialog dialog = MessagesController.getInstance(this.currentAccount).dialogs_dict.get(did);
            if (dialog != null) {
                dialog.notify_settings = new TLRPC.TL_peerNotifySettings();
            }
            NotificationsController.getInstance(this.currentAccount).updateServerNotificationsSettings(did);
        } else {
            SharedPreferences preferences2 = MessagesController.getNotificationsSettings(this.currentAccount);
            SharedPreferences.Editor editor2 = preferences2.edit();
            if (!defaultEnabled) {
                editor2.remove("notify2_" + did);
                flags = 0;
            } else {
                editor2.putInt("notify2_" + did, 2);
                flags = 1;
            }
            NotificationsController.getInstance(this.currentAccount).removeNotificationsForDialog(did);
            MessagesStorage.getInstance(this.currentAccount).setDialogFlags(did, flags);
            editor2.commit();
            TLRPC.Dialog dialog2 = MessagesController.getInstance(this.currentAccount).dialogs_dict.get(did);
            if (dialog2 != null) {
                dialog2.notify_settings = new TLRPC.TL_peerNotifySettings();
                if (defaultEnabled) {
                    dialog2.notify_settings.mute_until = Integer.MAX_VALUE;
                }
            }
            NotificationsController.getInstance(this.currentAccount).updateServerNotificationsSettings(did);
        }
        checkCell.setChecked(checked);
        RecyclerListView.Holder holder = (RecyclerListView.Holder) this.listView.findViewHolderForPosition(this.notifyRow);
        if (holder != null) {
            this.mAdapter.onBindViewHolder(holder, this.notifyRow);
        }
    }

    public /* synthetic */ void lambda$null$0$NewProfileActivity(int param) {
        if (param == 1) {
            NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.closeChats);
            NotificationCenter.getInstance(this.currentAccount).postNotificationName(NotificationCenter.closeChats, new Object[0]);
            finishFragment();
            return;
        }
        getNotificationCenter().postNotificationName(NotificationCenter.peerSettingsDidLoad, Long.valueOf(this.user_id));
    }

    public /* synthetic */ void lambda$null$1$NewProfileActivity(int which) {
        if (which == 1) {
            MessagesController.getInstance(this.currentAccount).blockUser(this.user_id);
            AlertsCreator.showSimpleToast(this, LocaleController.getString("UserBlacklisted", R.string.UserBlacklisted));
        }
    }

    private void updateRow() {
        TLRPC.User user = this.user;
        if (user == null) {
            return;
        }
        int i = 0;
        if (user.bot) {
            this.enableFriendMoment = false;
        }
        setViewData();
        this.rowCount = 0;
        this.headerRow = -1;
        this.phoneRow = -1;
        this.headerEmptyRow = -1;
        this.appCodeRow = -1;
        this.groupingAndRemarksRow = -1;
        this.hubRow = -1;
        this.hubEmptyRow = -1;
        this.signRow = -1;
        this.signEmptyRow = -1;
        this.notifyRow = -1;
        this.encriptEmptyRow = -1;
        this.encriptRow = -1;
        this.groupRow = -1;
        this.blockRow = -1;
        this.moreInfoRow = -1;
        this.photosRow = -1;
        this.filesRow = -1;
        this.linksRow = -1;
        this.audioRow = -1;
        this.voiceRow = -1;
        this.deleteContactRow = -1;
        this.sendToSelfEmptyRow = -1;
        this.sendToSelfRow = -1;
        this.addContactsEmptyRow = -1;
        this.addContactsRow = -1;
        if (this.forbidAddContact && !this.user.contact) {
            if (this.hasAdminRights) {
                int i2 = this.rowCount;
                this.rowCount = i2 + 1;
                this.headerRow = i2;
                TLRPC.User user2 = this.user;
                if (user2 == null || !TextUtils.isEmpty(user2.phone)) {
                }
                TLRPC.User user3 = this.user;
                if (user3 == null || TextUtils.isEmpty(user3.username) || (!this.user.contact && !this.user.self)) {
                }
                if (this.user.contact) {
                    int i3 = this.rowCount;
                    this.rowCount = i3 + 1;
                    this.groupingAndRemarksRow = i3;
                }
                int i4 = this.rowCount;
                int i5 = i4 + 1;
                this.rowCount = i5;
                this.headerEmptyRow = i4;
                if (this.enableFriendMoment) {
                    this.rowCount = i5 + 1;
                    this.hubRow = i5;
                }
                if (this.user.contact) {
                    int i6 = this.rowCount;
                    int i7 = i6 + 1;
                    this.rowCount = i7;
                    this.blockRow = i6;
                    int i8 = i7 + 1;
                    this.rowCount = i8;
                    this.notifyRow = i7;
                    this.rowCount = i8 + 1;
                    this.moreInfoRow = i8;
                } else if (!this.user.self && this.fromType == 2) {
                    int i9 = this.rowCount;
                    int i10 = i9 + 1;
                    this.rowCount = i10;
                    this.groupRow = i9;
                    int i11 = i10 + 1;
                    this.rowCount = i11;
                    this.blockRow = i10;
                    int i12 = i11 + 1;
                    this.rowCount = i12;
                    this.addContactsEmptyRow = i11;
                    this.rowCount = i12 + 1;
                    this.addContactsRow = i12;
                }
            } else {
                int i13 = this.rowCount;
                int i14 = i13 + 1;
                this.rowCount = i14;
                this.headerRow = i13;
                int i15 = i14 + 1;
                this.rowCount = i15;
                this.headerEmptyRow = i14;
                if (this.enableFriendMoment) {
                    this.rowCount = i15 + 1;
                    this.hubRow = i15;
                }
                int i16 = this.rowCount;
                this.rowCount = i16 + 1;
                this.blockRow = i16;
            }
        } else {
            int i17 = this.rowCount;
            this.rowCount = i17 + 1;
            this.headerRow = i17;
            TLRPC.User user4 = this.user;
            if (user4 == null || !TextUtils.isEmpty(user4.phone)) {
            }
            TLRPC.User user5 = this.user;
            if (user5 == null || TextUtils.isEmpty(user5.username) || (!this.user.contact && !this.user.self)) {
            }
            if (this.user.contact) {
                int i18 = this.rowCount;
                this.rowCount = i18 + 1;
                this.groupingAndRemarksRow = i18;
            }
            int i19 = this.rowCount;
            int i20 = i19 + 1;
            this.rowCount = i20;
            this.headerEmptyRow = i19;
            if (this.enableFriendMoment) {
                this.rowCount = i20 + 1;
                this.hubRow = i20;
            }
            if (this.currentEncryptedChat != null) {
                int i21 = this.rowCount;
                int i22 = i21 + 1;
                this.rowCount = i22;
                this.encriptEmptyRow = i21;
                this.rowCount = i22 + 1;
                this.encriptRow = i22;
            }
            if (this.user.contact) {
                int i23 = this.rowCount;
                int i24 = i23 + 1;
                this.rowCount = i24;
                this.notifyRow = i23;
                int i25 = i24 + 1;
                this.rowCount = i25;
                this.blockRow = i24;
                this.rowCount = i25 + 1;
                this.moreInfoRow = i25;
            } else if (!this.user.self && this.fromType == 2) {
                int i26 = this.rowCount;
                int i27 = i26 + 1;
                this.rowCount = i27;
                this.signEmptyRow = i26;
                int i28 = i27 + 1;
                this.rowCount = i28;
                this.groupRow = i27;
                int i29 = i28 + 1;
                this.rowCount = i29;
                this.blockRow = i28;
                int i30 = i29 + 1;
                this.rowCount = i30;
                this.addContactsEmptyRow = i29;
                this.rowCount = i30 + 1;
                this.addContactsRow = i30;
            } else if (UserObject.isDeleted(this.user)) {
                int i31 = this.rowCount;
                this.rowCount = i31 + 1;
                this.signEmptyRow = i31;
            }
        }
        if (this.user.self) {
            int i32 = this.rowCount;
            int i33 = i32 + 1;
            this.rowCount = i33;
            this.sendToSelfEmptyRow = i32;
            this.rowCount = i33 + 1;
            this.sendToSelfRow = i33;
            LinearLayout linearLayout = this.mLlBottomBtn;
            if (linearLayout != null) {
                linearLayout.setVisibility(8);
            }
        } else {
            LinearLayout linearLayout2 = this.mLlBottomBtn;
            if (linearLayout2 != null) {
                if (UserObject.isDeleted(this.user) || this.user.bot || ((!this.user.contact && this.fromType == 2) || (this.forbidAddContact && !this.user.contact && !this.hasAdminRights))) {
                    i = 8;
                }
                linearLayout2.setVisibility(i);
            }
        }
        MyAdapter myAdapter = this.mAdapter;
        if (myAdapter != null) {
            myAdapter.notifyDataSetChanged();
        }
    }

    private void setViewData() {
        TLRPC.User user = this.user;
        if (user != null) {
            if (user.self) {
                this.tvAddFriend.setVisibility(8);
                this.tvSecretChat.setVisibility(8);
            } else if (this.forbidAddContact && !this.user.contact) {
                if (!this.hasAdminRights) {
                    this.mLlBottomBtn.setVisibility(8);
                }
            } else if (!this.user.contact) {
                this.tvSendMessage.setVisibility(8);
                this.tvSecretChat.setVisibility(8);
                if (this.user.verified || this.user.bot || this.user.support) {
                    this.tvAddFriend.setVisibility(8);
                }
            } else {
                this.tvAddFriend.setVisibility(8);
                if (this.currentEncryptedChat != null) {
                    this.tvSecretChat.setVisibility(8);
                }
            }
        }
        TLRPCContacts.CL_userFull_v1 cL_userFull_v1 = this.userInfo;
        if (cL_userFull_v1 != null && cL_userFull_v1.getExtendBean() != null && this.userInfo.getExtendBean().userAlbumsReq != null) {
            if (this.parseUserFriendAlbumRunnable == null) {
                this.parseUserFriendAlbumRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.chats.-$$Lambda$NewProfileActivity$rG1gOm6hzVlV03P9sm7eTtmm1d4
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.parseUserFriendAlbums();
                    }
                };
            }
            Utilities.stageQueue.postRunnable(this.parseUserFriendAlbumRunnable);
            this.parseUserFriendAlbumRunnableIsRunning = true;
        }
        this.tvSecretChat.setVisibility(8);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void parseUserFriendAlbums() {
        TLRPCContacts.CL_userFull_v1_Bean.UserAlbumsBean userAlbumsReq;
        try {
            if (this.userInfo.getExtendBean().moment && (userAlbumsReq = this.userInfo.getExtendBean().userAlbumsReq) != null) {
                ArrayList<TLRPCContacts.CL_userFull_v1_Bean.Albums> albums = userAlbumsReq.albums;
                this.albumUrls = new ArrayList<>();
                if (albums != null && albums.size() > 0) {
                    for (int i = 0; i < albums.size(); i++) {
                        if (albums.get(i) != null && !TextUtils.isEmpty(albums.get(i).Thum)) {
                            this.albumUrls.add(HttpUtils.getInstance().getDownloadFileUrl() + albums.get(i).Thum);
                        }
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        this.parseUserFriendAlbumRunnableIsRunning = false;
    }

    private void loadMediaCounts() {
        if (this.dialog_id != 0) {
            MediaDataController.getInstance(this.currentAccount).getMediaCounts(this.dialog_id, this.classGuid);
        } else if (this.user_id != 0) {
            MediaDataController.getInstance(this.currentAccount).getMediaCounts(this.user_id, this.classGuid);
        }
    }

    @OnClick({R.attr.tv_add_friend, R.attr.tv_send_message, R.attr.tv_secret_chat})
    public void onClick(View view) {
        int id = view.getId();
        if (id == R.attr.tv_add_friend) {
            addContact();
        } else if (id == R.attr.tv_secret_chat) {
            startSecretChat();
        } else if (id == R.attr.tv_send_message) {
            sendMessage();
        }
    }

    private void addContact() {
        if (this.user != null) {
            Bundle bundle = new Bundle();
            bundle.putInt("from_type", this.fromType);
            presentFragment(new AddContactsInfoActivity(bundle, this.user));
        }
    }

    private void sendMessage() {
        TLRPC.User user = this.user;
        if (user == null || (user instanceof TLRPC.TL_userEmpty)) {
            return;
        }
        Bundle args = new Bundle();
        args.putInt("user_id", this.user_id);
        if (!MessagesController.getInstance(this.currentAccount).checkCanOpenChat(args, this)) {
            return;
        }
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.closeChats);
        NotificationCenter.getInstance(this.currentAccount).postNotificationName(NotificationCenter.closeChats, new Object[0]);
        presentFragment(new ChatActivity(args), true);
    }

    private void jumpToEditGreetActivity() {
        Bundle bundle = new Bundle();
        bundle.putInt("type", 0);
        GreetEditActivity greetEditActivity = new GreetEditActivity(bundle);
        greetEditActivity.setDelegate(new GreetEditActivity.GreetEditDelegate() { // from class: im.uwrkaxlmjj.ui.hui.chats.-$$Lambda$NewProfileActivity$8tktbrMMLtnwrronqgXprN4_N1E
            @Override // im.uwrkaxlmjj.ui.hui.contacts.GreetEditActivity.GreetEditDelegate
            public final void onFinish(String str) {
                this.f$0.startContactApply(str);
            }
        });
        presentFragment(greetEditActivity);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void startContactApply(String greet) {
        final XAlertDialog progressDialog = new XAlertDialog(getParentActivity(), 4);
        progressDialog.setLoadingText(LocaleController.getString(R.string.ApplySending));
        TLRPCContacts.ContactsRequestApply req = new TLRPCContacts.ContactsRequestApply();
        req.flag = 0;
        req.from_type = this.fromType;
        req.inputUser = getMessagesController().getInputUser(this.user);
        req.first_name = this.user.first_name;
        req.last_name = this.userNote;
        req.greet = greet;
        req.group_id = this.userGroupId;
        ConnectionsManager connectionsManager = getConnectionsManager();
        final int reqId = getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.chats.-$$Lambda$NewProfileActivity$hGISeoshduikSMdQWS7_ifRiBug
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$startContactApply$5$NewProfileActivity(progressDialog, tLObject, tL_error);
            }
        });
        connectionsManager.bindRequestToGuid(reqId, this.classGuid);
        progressDialog.setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: im.uwrkaxlmjj.ui.hui.chats.-$$Lambda$NewProfileActivity$YXz38FbNzcZR7VYh8kQ1KpzqRWQ
            @Override // android.content.DialogInterface.OnCancelListener
            public final void onCancel(DialogInterface dialogInterface) {
                this.f$0.lambda$startContactApply$6$NewProfileActivity(reqId, dialogInterface);
            }
        });
        progressDialog.show();
    }

    public /* synthetic */ void lambda$startContactApply$5$NewProfileActivity(final XAlertDialog progressDialog, final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.chats.-$$Lambda$NewProfileActivity$fotnz2cfao_sriQjM4UH95jW1-8
            @Override // java.lang.Runnable
            public final void run() throws Exception {
                this.f$0.lambda$null$4$NewProfileActivity(error, progressDialog, response);
            }
        });
    }

    public /* synthetic */ void lambda$null$4$NewProfileActivity(TLRPC.TL_error error, final XAlertDialog progressDialog, TLObject response) throws Exception {
        TLRPC.TL_updates updates;
        if (error != null) {
            progressDialog.dismiss();
            ToastUtils.show((CharSequence) ContactsUtils.getAboutContactsErrText(error));
            return;
        }
        if ((response instanceof TLRPC.TL_updates) && (updates = (TLRPC.TL_updates) response) != null && updates.updates != null) {
            getMessagesController().processUpdates(updates, false);
            for (int i = 0; i < updates.updates.size(); i++) {
                if (updates.updates.get(i) instanceof TLRPCContacts.ContactApplyResp) {
                    TLRPCContacts.ContactApplyResp res = (TLRPCContacts.ContactApplyResp) updates.updates.get(i);
                    getMessagesController().saveContactsAppliesId(res.applyInfo.id);
                }
            }
        }
        progressDialog.setLoadingImage(this.mContext.getResources().getDrawable(R.id.ic_apply_send_done), AndroidUtilities.dp(30.0f), AndroidUtilities.dp(20.0f));
        progressDialog.setLoadingText(LocaleController.getString(R.string.ApplySent));
        this.fragmentView.postDelayed(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.chats.-$$Lambda$NewProfileActivity$o0hbATmw9a2dj4cGBNReQuCQSPk
            @Override // java.lang.Runnable
            public final void run() {
                progressDialog.dismiss();
            }
        }, AdaptiveTrackSelection.DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS);
    }

    public /* synthetic */ void lambda$startContactApply$6$NewProfileActivity(int reqId, DialogInterface dialog) {
        getConnectionsManager().cancelRequest(reqId, true);
    }

    private void startSecretChat() {
        XDialog.Builder builder = new XDialog.Builder(getParentActivity());
        builder.setTitle(LocaleController.getString("AreYouSureSecretChatTitle", R.string.AreYouSureSecretChatTitle));
        builder.setMessage(LocaleController.getString("AreYouSureSecretChat", R.string.AreYouSureSecretChat));
        builder.setPositiveButton(LocaleController.getString("Start", R.string.Start), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.chats.-$$Lambda$NewProfileActivity$AHT_TUqVsoPeCKeLU1L7dbafj_w
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                this.f$0.lambda$startSecretChat$7$NewProfileActivity(dialogInterface, i);
            }
        });
        builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
        showDialog(builder.create());
    }

    public /* synthetic */ void lambda$startSecretChat$7$NewProfileActivity(DialogInterface dialogInterface, int i) {
        this.creatingChat = true;
        SecretChatHelper.getInstance(this.currentAccount).startSecretChat(getParentActivity(), MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(this.user_id)));
    }

    private void deleteContact() {
        if (this.user == null || getParentActivity() == null) {
            return;
        }
        XDialog.Builder builder = new XDialog.Builder(getParentActivity());
        builder.setTitle(LocaleController.getString("DeleteContact", R.string.DeleteContact));
        builder.setMessage(LocaleController.getString("AreYouSureDeleteContact", R.string.AreYouSureDeleteContact));
        builder.setPositiveButton(LocaleController.getString("Delete", R.string.Delete), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.chats.-$$Lambda$NewProfileActivity$sm6jDeWgUmlJ0tTB8Ha1hbFg7uA
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                this.f$0.lambda$deleteContact$9$NewProfileActivity(dialogInterface, i);
            }
        });
        builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
        XDialog dialog = builder.create();
        showDialog(dialog);
        TextView button = (TextView) dialog.getButton(-1);
        if (button != null) {
            button.setTextColor(Theme.getColor(Theme.key_dialogTextRed2));
        }
    }

    public /* synthetic */ void lambda$deleteContact$9$NewProfileActivity(DialogInterface dialogInterface, int i) {
        ArrayList<TLRPC.User> arrayList = new ArrayList<>();
        arrayList.add(this.user);
        ContactsController.getInstance(this.currentAccount).deleteContact(arrayList);
        getMessagesController().deleteDialog(this.user.id, 0);
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.chats.-$$Lambda$NewProfileActivity$8HHiVuWuahhEWT-f6dvh0ThBWMY
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$8$NewProfileActivity();
            }
        });
    }

    public /* synthetic */ void lambda$null$8$NewProfileActivity() {
        getNotificationCenter().postNotificationName(NotificationCenter.closeChats, new Object[0]);
        finishFragment();
    }

    private void showBolckedUserListDialog() {
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, final Object... args) {
        int i;
        int i2;
        RecyclerListView.Holder holder;
        RecyclerListView recyclerListView;
        RecyclerListView.Holder holder2;
        if (id == NotificationCenter.updateInterfaces) {
            int mask = ((Integer) args[0]).intValue();
            if (this.user_id != 0) {
                if (((mask & 2) != 0 || (mask & 1) != 0 || (mask & 4) != 0) && (holder = (RecyclerListView.Holder) this.listView.findViewHolderForPosition(this.headerRow)) != null) {
                    this.mAdapter.onBindViewHolder(holder, this.headerRow);
                }
                if ((mask & 1024) != 0 && (recyclerListView = this.listView) != null && (holder2 = (RecyclerListView.Holder) recyclerListView.findViewHolderForPosition(this.phoneRow)) != null) {
                    this.mAdapter.onBindViewHolder(holder2, this.phoneRow);
                    return;
                }
                return;
            }
            return;
        }
        if (id == NotificationCenter.encryptedChatCreated) {
            if (this.creatingChat) {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.chats.-$$Lambda$NewProfileActivity$Q9MSpCroMP5ANO4kNwyVFxpWZW0
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$didReceivedNotification$10$NewProfileActivity(args);
                    }
                });
                return;
            }
            return;
        }
        if (id == NotificationCenter.blockedUsersDidLoad) {
            boolean oldValue = this.userBlocked;
            boolean z = MessagesController.getInstance(this.currentAccount).blockedUsers.indexOfKey(this.user_id) >= 0;
            this.userBlocked = z;
            if (oldValue != z) {
                updateRow();
                this.mAdapter.notifyDataSetChanged();
                return;
            }
            return;
        }
        if (id != NotificationCenter.mediaCountsDidLoad) {
            if (id != NotificationCenter.mediaCountDidLoad) {
                if (id != NotificationCenter.userFullInfoDidLoad) {
                    if (id == NotificationCenter.groupingChanged) {
                        MessagesController.getInstance(this.currentAccount).loadFullUser(this.user_id, this.classGuid, true);
                        return;
                    } else {
                        int i3 = NotificationCenter.botInfoDidLoad;
                        return;
                    }
                }
                if (((Integer) args[0]).intValue() == this.user_id && (args[1] instanceof TLRPCContacts.CL_userFull_v1)) {
                    TLRPCContacts.CL_userFull_v1 cL_userFull_v1 = (TLRPCContacts.CL_userFull_v1) args[1];
                    this.userInfo = cL_userFull_v1;
                    this.user = cL_userFull_v1.user;
                    updateRow();
                    return;
                }
                return;
            }
            long uid = ((Long) args[0]).longValue();
            long did = this.dialog_id;
            if (did == 0 && (i = this.user_id) != 0) {
                did = i;
            }
            if (uid == did) {
                int type = ((Integer) args[3]).intValue();
                int mCount = ((Integer) args[1]).intValue();
                if (uid == did) {
                    this.mediaCount[type] = mCount;
                }
                int[] iArr = this.prevMediaCount;
                int[] iArr2 = this.lastMediaCount;
                iArr[type] = iArr2[type];
                int[] iArr3 = this.mediaCount;
                if (iArr3[type] >= 0 || iArr3[type] >= 0) {
                    iArr2[type] = iArr3[type];
                } else {
                    iArr2[type] = 0;
                }
                updateRow();
                return;
            }
            return;
        }
        long uid2 = ((Long) args[0]).longValue();
        long did2 = this.dialog_id;
        if (did2 == 0 && (i2 = this.user_id) != 0) {
            did2 = i2;
        }
        if (uid2 == did2) {
            int[] counts = (int[]) args[1];
            if (uid2 == did2) {
                this.mediaCount = counts;
            }
            int[] iArr4 = this.lastMediaCount;
            int[] iArr5 = this.prevMediaCount;
            System.arraycopy(iArr4, 0, iArr5, 0, iArr5.length);
            int a = 0;
            while (true) {
                int[] iArr6 = this.lastMediaCount;
                if (a < iArr6.length) {
                    int[] iArr7 = this.mediaCount;
                    if (iArr7[a] >= 0 || iArr7[a] >= 0) {
                        iArr6[a] = iArr7[a];
                    } else {
                        iArr6[a] = 0;
                    }
                    if (uid2 == did2 && this.lastMediaCount[a] != 0) {
                        MediaDataController.getInstance(this.currentAccount).loadMedia(did2, 50, 0, a, 2, this.classGuid);
                    }
                    a++;
                } else {
                    updateRow();
                    return;
                }
            }
        }
    }

    public /* synthetic */ void lambda$didReceivedNotification$10$NewProfileActivity(Object[] args) {
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.closeChats);
        NotificationCenter.getInstance(this.currentAccount).postNotificationName(NotificationCenter.closeChats, new Object[0]);
        TLRPC.EncryptedChat encryptedChat = (TLRPC.EncryptedChat) args[0];
        Bundle args2 = new Bundle();
        args2.putInt("enc_id", encryptedChat.id);
        presentFragment(new ChatActivity(args2), true);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.mediaCountDidLoad);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.mediaCountsDidLoad);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.mediaDidLoad);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.didReceiveNewMessages);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.messagesDeleted);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.closeChats);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.botInfoDidLoad);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.userFullInfoDidLoad);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.blockedUsersDidLoad);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.encryptedChatUpdated);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.encryptedChatCreated);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.contactsDidLoad);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.updateInterfaces);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.groupingChanged);
        super.onFragmentDestroy();
        if (this.parseUserFriendAlbumRunnable != null && this.parseUserFriendAlbumRunnableIsRunning) {
            Utilities.stageQueue.cancelRunnable(this.parseUserFriendAlbumRunnable);
        }
        this.userInfo = null;
        this.currentEncryptedChat = null;
        this.sharedMediaData = null;
        this.parseUserFriendAlbumRunnableIsRunning = false;
    }

    /* JADX INFO: Access modifiers changed from: private */
    class MyAdapter extends RecyclerListView.SelectionAdapter {
        private TextView mTvNickName;

        private MyAdapter() {
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            int position = holder.getAdapterPosition();
            return position == NewProfileActivity.this.phoneRow || position == NewProfileActivity.this.hubRow || position == NewProfileActivity.this.photosRow || position == NewProfileActivity.this.encriptRow || position == NewProfileActivity.this.filesRow || position == NewProfileActivity.this.linksRow || position == NewProfileActivity.this.audioRow || position == NewProfileActivity.this.voiceRow || position == NewProfileActivity.this.notifyRow || position == NewProfileActivity.this.groupRow || position == NewProfileActivity.this.appCodeRow || position == NewProfileActivity.this.blockRow || position == NewProfileActivity.this.groupingAndRemarksRow || position == NewProfileActivity.this.moreInfoRow || position == NewProfileActivity.this.deleteContactRow || position == NewProfileActivity.this.sendToSelfRow;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view = null;
            if (viewType == 0) {
                view = new TextSettingCell(NewProfileActivity.this.mContext);
                view.setLayoutParams(new RecyclerView.LayoutParams(-1, -2));
                view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
            } else if (viewType == 1) {
                view = LayoutInflater.from(NewProfileActivity.this.mContext).inflate(R.layout.item_profile_header, parent, false);
                view.setLayoutParams(new RecyclerView.LayoutParams(-1, -2));
            } else if (viewType == 2) {
                view = new MryTextCheckCell(NewProfileActivity.this.mContext);
                view.setLayoutParams(new RecyclerView.LayoutParams(-1, -2));
                view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
            } else if (viewType == 3) {
                view = new ShadowSectionCell(NewProfileActivity.this.mContext);
            } else if (viewType == 4) {
                view = LayoutInflater.from(NewProfileActivity.this.mContext).inflate(R.layout.item_send_to_self, parent, false);
            } else if (viewType == 8) {
                view = new PhotoCell(NewProfileActivity.this.mContext);
                view.setPadding(AndroidUtilities.dp(20.0f), 0, 0, 0);
                RelativeLayout.LayoutParams layoutParams = new RelativeLayout.LayoutParams(-1, AndroidUtilities.dp(65.0f));
                view.setLayoutParams(layoutParams);
            }
            return new RecyclerListView.Holder(view);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            int i;
            int i2;
            String str;
            View view = holder.itemView;
            int itemViewType = holder.getItemViewType();
            boolean z = false;
            if (itemViewType == 0) {
                TextSettingCell textCell = (TextSettingCell) view;
                textCell.getTextView().setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
                if (position != NewProfileActivity.this.appCodeRow) {
                    if (position != NewProfileActivity.this.phoneRow) {
                        if (position == NewProfileActivity.this.groupingAndRemarksRow) {
                            textCell.setTextAndValue(LocaleController.getString("GroupingAndRemarks", R.string.GroupingAndRemarks), (NewProfileActivity.this.userInfo == null || NewProfileActivity.this.userInfo.getExtendBean() == null) ? "" : NewProfileActivity.this.userInfo.getExtendBean().group_name, false, true);
                        } else if (position != NewProfileActivity.this.hubRow) {
                            if (position == NewProfileActivity.this.signRow) {
                                textCell.setTextAndValue(LocaleController.getString("BioDesc", R.string.BioDesc), (NewProfileActivity.this.userInfo == null || TextUtils.isEmpty(NewProfileActivity.this.userInfo.about)) ? LocaleController.getString(R.string.BioNothing) : NewProfileActivity.this.userInfo.about, false, false);
                            } else if (position == NewProfileActivity.this.photosRow) {
                                textCell.setTextAndValue(LocaleController.getString("SharedPhotosAndVideos", R.string.SharedPhotosAndVideos), String.format("%d", Integer.valueOf(NewProfileActivity.this.lastMediaCount[0])), position != NewProfileActivity.this.rowCount - 1, true);
                            } else if (position != NewProfileActivity.this.filesRow) {
                                if (position != NewProfileActivity.this.linksRow) {
                                    if (position != NewProfileActivity.this.audioRow) {
                                        if (position != NewProfileActivity.this.voiceRow) {
                                            if (position != NewProfileActivity.this.groupRow) {
                                                if (position != NewProfileActivity.this.encriptRow) {
                                                    if (position == NewProfileActivity.this.moreInfoRow) {
                                                        textCell.setText(LocaleController.getString("MoreInformation", R.string.MoreInformation), position != NewProfileActivity.this.rowCount - 1, true);
                                                    } else if (position == NewProfileActivity.this.deleteContactRow) {
                                                        textCell.getTextView().setTextColor(NewProfileActivity.this.mContext.getResources().getColor(R.color.color_item_menu_red_f74c31));
                                                        textCell.setText(LocaleController.getString("DeleteContact", R.string.DeleteContact), false, false);
                                                    }
                                                } else {
                                                    IdenticonDrawable identiconDrawable = new IdenticonDrawable();
                                                    TLRPC.EncryptedChat encryptedChat = MessagesController.getInstance(NewProfileActivity.this.currentAccount).getEncryptedChat(Integer.valueOf((int) (NewProfileActivity.this.dialog_id >> 32)));
                                                    if (encryptedChat instanceof TLRPC.TL_encryptedChat) {
                                                        identiconDrawable.setEncryptedChat(encryptedChat);
                                                        textCell.setTextAndValueDrawable(LocaleController.getString("EncryptionKey", R.string.EncryptionKey), identiconDrawable, false);
                                                        textCell.setEnabled(true);
                                                    } else {
                                                        textCell.setTextAndValue(LocaleController.getString("EncryptionKey", R.string.EncryptionKey), "loading", false);
                                                        textCell.setEnabled(false);
                                                    }
                                                }
                                            } else {
                                                String string = LocaleController.getString("GroupsInCommonTitle", R.string.GroupsInCommonTitle);
                                                Object[] objArr = new Object[1];
                                                objArr[0] = Integer.valueOf(NewProfileActivity.this.userInfo != null ? NewProfileActivity.this.userInfo.common_chats_count : 0);
                                                textCell.setTextAndValue(string, String.format("%d个", objArr), position != NewProfileActivity.this.rowCount - 1, true);
                                            }
                                        } else {
                                            textCell.setTextAndValue(LocaleController.getString("AudioAutodownload", R.string.AudioAutodownload), String.format("%d", Integer.valueOf(NewProfileActivity.this.lastMediaCount[2])), position != NewProfileActivity.this.rowCount - 1, true);
                                        }
                                    } else {
                                        textCell.setTextAndValue(LocaleController.getString("SharedAudioFiles", R.string.SharedAudioFiles), String.format("%d", Integer.valueOf(NewProfileActivity.this.lastMediaCount[4])), position != NewProfileActivity.this.rowCount - 1, true);
                                    }
                                } else {
                                    textCell.setTextAndValue(LocaleController.getString("SharedLinks", R.string.SharedLinks), String.format("%d", Integer.valueOf(NewProfileActivity.this.lastMediaCount[3])), position != NewProfileActivity.this.rowCount - 1, true);
                                }
                            } else {
                                textCell.setTextAndValue(LocaleController.getString("FilesDataUsage", R.string.FilesDataUsage), String.format("%d", Integer.valueOf(NewProfileActivity.this.lastMediaCount[1])), position != NewProfileActivity.this.rowCount - 1, true);
                            }
                        } else {
                            textCell.setText(LocaleController.getString("FriendHub", R.string.FriendHub), true, true);
                        }
                    } else {
                        TLRPC.User user = null;
                        if (NewProfileActivity.this.userInfo != null && NewProfileActivity.this.userInfo.user != null) {
                            user = NewProfileActivity.this.userInfo.user;
                        }
                        if (user == null) {
                            user = NewProfileActivity.this.getMessagesController().getUser(Integer.valueOf(NewProfileActivity.this.user_id));
                        }
                        if (user == null || TextUtils.isEmpty(user.phone)) {
                            textCell.setVisibility(8);
                        } else {
                            textCell.setText(LocaleController.getString("PhoneNumberSearch", R.string.PhoneNumberSearch) + ": " + user.phone, NewProfileActivity.this.groupingAndRemarksRow != -1, false);
                        }
                    }
                } else {
                    TLRPC.User user2 = null;
                    if (NewProfileActivity.this.userInfo != null && NewProfileActivity.this.userInfo.user != null) {
                        user2 = NewProfileActivity.this.userInfo.user;
                    }
                    if (user2 == null) {
                        user2 = NewProfileActivity.this.getMessagesController().getUser(Integer.valueOf(NewProfileActivity.this.user_id));
                    }
                    if (user2 == null || TextUtils.isEmpty(user2.username)) {
                        textCell.setVisibility(8);
                    }
                }
                if ((NewProfileActivity.this.user.self && position == NewProfileActivity.this.rowCount - 3) || (!NewProfileActivity.this.user.self && position == NewProfileActivity.this.rowCount - 1)) {
                    view.setBackground(Theme.createRoundRectDrawable(0.0f, 0.0f, AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
                    return;
                }
                return;
            }
            if (itemViewType != 1) {
                if (itemViewType != 2) {
                    if (itemViewType != 4) {
                        if (itemViewType == 8) {
                            PhotoCell photoCell = (PhotoCell) view;
                            photoCell.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                            photoCell.setText(LocaleController.getString("FriendHub", R.string.FriendHub), true);
                            photoCell.setData(NewProfileActivity.this.albumUrls == null ? new ArrayList<>() : NewProfileActivity.this.albumUrls);
                            photoCell.setListener(new PhotoCell.OnPhotoCellClickListener() { // from class: im.uwrkaxlmjj.ui.hui.chats.NewProfileActivity.MyAdapter.3
                                @Override // im.uwrkaxlmjj.ui.hcells.PhotoCell.OnPhotoCellClickListener
                                public void onPhotoClick(ImageView view2, int position2, String url) {
                                    if (NewProfileActivity.this.user != null || NewProfileActivity.this.user_id != 0) {
                                        if (NewProfileActivity.this.user_id != NewProfileActivity.this.getUserConfig().getClientUserId()) {
                                            NewProfileActivity.this.presentFragment(new FcPageOthersActivity(NewProfileActivity.this.user_id, NewProfileActivity.this.user.access_hash));
                                        } else {
                                            NewProfileActivity.this.presentFragment(new FcPageMineActivity());
                                        }
                                    }
                                }
                            });
                            return;
                        }
                        return;
                    }
                    ImageView ivSend = (ImageView) view.findViewById(R.attr.iv_send);
                    MryTextView tvSend = (MryTextView) view.findViewById(R.attr.tv_send);
                    if (position != NewProfileActivity.this.sendToSelfRow) {
                        if (position == NewProfileActivity.this.addContactsRow) {
                            tvSend.setText(LocaleController.getString("AddToContacts", R.string.AddToContacts));
                            ivSend.setVisibility(8);
                            view.setBackground(Theme.createRoundRectDrawable(0.0f, 0.0f, AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
                            return;
                        }
                        return;
                    }
                    view.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
                    return;
                }
                MryTextCheckCell checkCell = (MryTextCheckCell) view;
                if (position == NewProfileActivity.this.notifyRow) {
                    SharedPreferences preferences = MessagesController.getNotificationsSettings(NewProfileActivity.this.currentAccount);
                    long did = NewProfileActivity.this.dialog_id != 0 ? NewProfileActivity.this.dialog_id : NewProfileActivity.this.user_id;
                    boolean enabled = false;
                    boolean hasOverride = preferences.contains("notify2_" + did);
                    int value = preferences.getInt("notify2_" + did, 0);
                    int delta = preferences.getInt("notifyuntil_" + did, 0);
                    if (value == 3 && delta != Integer.MAX_VALUE) {
                        if (delta - ConnectionsManager.getInstance(NewProfileActivity.this.currentAccount).getCurrentTime() <= 0) {
                            enabled = true;
                        }
                    } else if (value == 0) {
                        if (!hasOverride) {
                            enabled = NotificationsController.getInstance(NewProfileActivity.this.currentAccount).isGlobalNotificationsEnabled(did);
                        } else {
                            enabled = true;
                        }
                    } else if (value == 1) {
                        enabled = true;
                    } else if (value == 2) {
                        enabled = false;
                    } else {
                        enabled = false;
                    }
                    checkCell.setTextAndCheck(LocaleController.getString("MessageNotifications", R.string.MessageNotifications), enabled, true);
                    return;
                }
                if (position == NewProfileActivity.this.blockRow) {
                    if (NewProfileActivity.this.userBlocked) {
                        i2 = R.string.RemoveToBlacklist;
                        str = "RemoveToBlacklist";
                    } else {
                        i2 = R.string.AddToBlacklist;
                        str = "AddToBlacklist";
                    }
                    String string2 = LocaleController.getString(str, i2);
                    boolean z2 = NewProfileActivity.this.userBlocked;
                    if ((NewProfileActivity.this.user.contact || NewProfileActivity.this.fromType != 2) && position != NewProfileActivity.this.rowCount - 1) {
                        z = true;
                    }
                    checkCell.setTextAndCheck(string2, z2, z);
                    if (position == NewProfileActivity.this.rowCount - 1) {
                        checkCell.setBackground(Theme.createRoundRectDrawable(0.0f, 0.0f, AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
                        return;
                    }
                    return;
                }
                return;
            }
            TextView txtAccount = (TextView) view.findViewById(R.attr.tv_account);
            final BackupImageView ivAvatar = (BackupImageView) view.findViewById(R.attr.iv_avatar);
            ivAvatar.setRoundRadius(AndroidUtilities.dp(7.5f));
            ivAvatar.setPivotX(0.0f);
            ivAvatar.setPivotY(0.0f);
            ivAvatar.setContentDescription(LocaleController.getString("AccDescrProfilePicture", R.string.AccDescrProfilePicture));
            TextView textView = (TextView) view.findViewById(R.attr.tv_nick_name);
            this.mTvNickName = textView;
            textView.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
            ImageView ivGender = (ImageView) view.findViewById(R.attr.iv_gender);
            ivGender.setVisibility(8);
            TextView tvUpdateTime = (TextView) view.findViewById(R.attr.tv_update_time);
            MryRoundButton btnBotFollow = (MryRoundButton) view.findViewById(R.attr.btnBotFollow);
            ImageView ivCall = (ImageView) view.findViewById(R.attr.iv_call);
            View divider = view.findViewById(R.attr.divider);
            divider.setBackgroundColor(Theme.getColor(Theme.key_divider));
            if (NewProfileActivity.this.phoneRow == -1 && NewProfileActivity.this.appCodeRow == -1 && NewProfileActivity.this.groupingAndRemarksRow == -1) {
                divider.setVisibility(8);
            }
            ivCall.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_windowBackgroundWhiteBlueButton), PorterDuff.Mode.SRC_IN));
            ivCall.setBackground(Theme.createSelectorDrawable(Theme.getColor(Theme.key_actionBarDefaultSelector)));
            ivCall.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.chats.-$$Lambda$NewProfileActivity$MyAdapter$XxZc3Xf52TvQRGf8XSCjZt6DRQI
                @Override // android.view.View.OnClickListener
                public final void onClick(View view2) {
                    this.f$0.lambda$onBindViewHolder$0$NewProfileActivity$MyAdapter(view2);
                }
            });
            ivCall.setVisibility(8);
            if (NewProfileActivity.this.userInfo != null && NewProfileActivity.this.userInfo.getExtendBean() != null) {
                int sex = NewProfileActivity.this.userInfo.getExtendBean().sex;
                ivGender.setImageResource(sex == 1 ? R.id.ic_male : sex == 2 ? R.id.ic_female : 0);
                ivGender.setVisibility(0);
            } else {
                ivGender.setVisibility(8);
            }
            TLRPC.User user3 = (NewProfileActivity.this.userInfo == null || NewProfileActivity.this.userInfo.user == null) ? NewProfileActivity.this.getMessagesController().getUser(Integer.valueOf(NewProfileActivity.this.user_id)) : NewProfileActivity.this.userInfo.user;
            if (user3 != null && user3.contact && user3.username != null && !"null".equals(user3.username)) {
                txtAccount.setText(LocaleController.getString("AppNameCode", R.string.AppNameCode) + LogUtils.COLON + user3.username);
                i = 8;
            } else {
                i = 8;
                txtAccount.setVisibility(8);
            }
            txtAccount.setVisibility(i);
            if ((user3.self && position == NewProfileActivity.this.rowCount - 3) || (!user3.self && position == NewProfileActivity.this.rowCount - 1)) {
                view.setBackground(Theme.createRoundRectDrawable(0.0f, 0.0f, AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
            }
            if (user3 != null) {
                AvatarDrawable avatarDrawable = new AvatarDrawable(user3);
                avatarDrawable.setColor(Theme.getColor(Theme.key_avatar_backgroundInProfileBlue));
                ivAvatar.setImage(ImageLocation.getForUser(user3, false), "50_50", avatarDrawable, user3);
                if (!user3.bot) {
                    tvUpdateTime.setText(LocaleController.formatUserStatus(NewProfileActivity.this.currentAccount, user3, null));
                } else {
                    tvUpdateTime.setText(LocaleController.getString(R.string.Bot));
                }
                this.mTvNickName.setText(user3.first_name);
                if (!user3.contact || user3.bot) {
                    ivCall.setVisibility(8);
                }
                if (user3.bot && NewProfileActivity.this.userInfo != null) {
                    btnBotFollow.setPrimaryRadiusAdjustBoundsStrokeStyle();
                    if (!NewProfileActivity.this.userBlocked) {
                        btnBotFollow.setCompoundDrawablesWithIntrinsicBounds(ContextCompat.getDrawable(NewProfileActivity.this.getParentActivity(), R.id.ic_bot_followed), (Drawable) null, (Drawable) null, (Drawable) null);
                        btnBotFollow.setStrokeData(AndroidUtilities.dp(0.5f), -4473925);
                        btnBotFollow.setTextColor(-8882056);
                        btnBotFollow.setText(LocaleController.getString(R.string.attentioned));
                    } else {
                        btnBotFollow.setCompoundDrawablesWithIntrinsicBounds(ContextCompat.getDrawable(NewProfileActivity.this.getParentActivity(), R.id.ic_bot_follow), (Drawable) null, (Drawable) null, (Drawable) null);
                        btnBotFollow.setStrokeData(AndroidUtilities.dp(0.5f), -367616);
                        btnBotFollow.setTextColor(-367616);
                        btnBotFollow.setText(LocaleController.getString(R.string.attention));
                    }
                    if (btnBotFollow.getVisibility() != 0) {
                        btnBotFollow.setVisibility(0);
                    }
                    btnBotFollow.setOnClickListener(new AnonymousClass1(user3));
                } else if (btnBotFollow.getVisibility() != 8) {
                    btnBotFollow.setVisibility(8);
                }
                final PhotoViewer.PhotoViewerProvider provider = new PhotoViewer.EmptyPhotoViewerProvider() { // from class: im.uwrkaxlmjj.ui.hui.chats.NewProfileActivity.MyAdapter.2
                    @Override // im.uwrkaxlmjj.ui.PhotoViewer.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
                    public PhotoViewer.PlaceProviderObject getPlaceForPhoto(MessageObject messageObject, TLRPC.FileLocation fileLocation, int index, boolean needPreview) {
                        TLRPC.Chat chat;
                        if (fileLocation == null || NewProfileActivity.this.isFinishing()) {
                            return null;
                        }
                        TLRPC.FileLocation photoBig = null;
                        if (NewProfileActivity.this.user_id != 0) {
                            TLRPC.User user4 = MessagesController.getInstance(NewProfileActivity.this.currentAccount).getUser(Integer.valueOf(NewProfileActivity.this.user_id));
                            if (user4 != null && user4.photo != null && user4.photo.photo_big != null) {
                                photoBig = user4.photo.photo_big;
                            }
                        } else if (NewProfileActivity.this.dialog_id != 0 && (chat = MessagesController.getInstance(NewProfileActivity.this.currentAccount).getChat(Integer.valueOf((int) NewProfileActivity.this.dialog_id))) != null && chat.photo != null && chat.photo.photo_big != null) {
                            photoBig = chat.photo.photo_big;
                        }
                        if (photoBig == null || photoBig.local_id != fileLocation.local_id || photoBig.volume_id != fileLocation.volume_id || photoBig.dc_id != fileLocation.dc_id) {
                            return null;
                        }
                        int[] coords = new int[2];
                        ivAvatar.getLocationInWindow(coords);
                        PhotoViewer.PlaceProviderObject object = new PhotoViewer.PlaceProviderObject();
                        object.viewX = coords[0];
                        object.viewY = coords[1];
                        object.parentView = ivAvatar;
                        object.imageReceiver = ivAvatar.getImageReceiver();
                        if (NewProfileActivity.this.user_id != 0) {
                            object.dialogId = NewProfileActivity.this.user_id;
                        } else if (NewProfileActivity.this.dialog_id != 0) {
                            object.dialogId = (int) (-NewProfileActivity.this.dialog_id);
                        }
                        object.thumb = object.imageReceiver.getBitmapSafe();
                        object.size = -1;
                        object.radius = ivAvatar.getImageReceiver().getRoundRadius();
                        object.scale = ivAvatar.getScaleX();
                        return object;
                    }

                    @Override // im.uwrkaxlmjj.ui.PhotoViewer.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
                    public void willHidePhotoViewer() {
                        ivAvatar.getImageReceiver().setVisible(true, true);
                    }
                };
                ivAvatar.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.chats.-$$Lambda$NewProfileActivity$MyAdapter$9PXeLI0OfrdqTsHg4io7eWiVN5Y
                    @Override // android.view.View.OnClickListener
                    public final void onClick(View view2) {
                        this.f$0.lambda$onBindViewHolder$1$NewProfileActivity$MyAdapter(provider, view2);
                    }
                });
            }
            this.mTvNickName.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        }

        public /* synthetic */ void lambda$onBindViewHolder$0$NewProfileActivity$MyAdapter(View v) {
            TLRPC.User user = MessagesController.getInstance(NewProfileActivity.this.currentAccount).getUser(Integer.valueOf(NewProfileActivity.this.user_id));
            if (user != null) {
                NewProfileActivity.this.startCall(user);
            }
        }

        /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.hui.chats.NewProfileActivity$MyAdapter$1, reason: invalid class name */
        class AnonymousClass1 implements View.OnClickListener {
            final /* synthetic */ TLRPC.User val$user;

            AnonymousClass1(TLRPC.User user) {
                this.val$user = user;
            }

            @Override // android.view.View.OnClickListener
            public void onClick(View v) {
                if (NewProfileActivity.this.userBlocked) {
                    MessagesController.getInstance(NewProfileActivity.this.currentAccount).unblockUser(NewProfileActivity.this.user_id);
                    SendMessagesHelper.getInstance(NewProfileActivity.this.currentAccount).sendMessage("/start", NewProfileActivity.this.user_id, null, null, false, null, null, null, true, 0);
                    NewProfileActivity.this.finishFragment();
                    return;
                }
                List<String> arrList = new ArrayList<>();
                arrList.add(LocaleController.formatString("AreYouSureBlockContact3", R.string.AreYouSureBlockContact3, ContactsController.formatName(this.val$user.first_name, this.val$user.last_name)));
                arrList.add(LocaleController.getString("fc_cancel_followed", R.string.fc_cancel_followed));
                int[] iTextColor = {-7631463, -570319};
                DialogCommonList dialogCommonList = new DialogCommonList(NewProfileActivity.this.getParentActivity(), arrList, (List<Integer>) null, iTextColor, new DialogCommonList.RecyclerviewItemClickCallBack() { // from class: im.uwrkaxlmjj.ui.hui.chats.-$$Lambda$NewProfileActivity$MyAdapter$1$RgyhkUm0lZRZdoW15QoWFxZCV-A
                    @Override // im.uwrkaxlmjj.ui.dialogs.DialogCommonList.RecyclerviewItemClickCallBack
                    public final void onRecyclerviewItemClick(int i) {
                        this.f$0.lambda$onClick$0$NewProfileActivity$MyAdapter$1(i);
                    }
                }, 1);
                dialogCommonList.setCancle(Color.parseColor("#222222"), 16);
                dialogCommonList.show();
            }

            public /* synthetic */ void lambda$onClick$0$NewProfileActivity$MyAdapter$1(int which) {
                if (which == 1) {
                    MessagesController.getInstance(NewProfileActivity.this.currentAccount).blockUser(NewProfileActivity.this.user_id);
                }
            }
        }

        public /* synthetic */ void lambda$onBindViewHolder$1$NewProfileActivity$MyAdapter(PhotoViewer.PhotoViewerProvider provider, View v) {
            if (!NewProfileActivity.this.isFinishing()) {
                if (NewProfileActivity.this.user_id != 0) {
                    TLRPC.User user1 = MessagesController.getInstance(NewProfileActivity.this.currentAccount).getUser(Integer.valueOf(NewProfileActivity.this.user_id));
                    if (user1.photo != null && user1.photo.photo_big != null) {
                        PhotoViewer.getInstance().setParentActivity(NewProfileActivity.this.getParentActivity());
                        if (user1.photo.dc_id != 0) {
                            user1.photo.photo_big.dc_id = user1.photo.dc_id;
                        }
                        PhotoViewer.getInstance().openPhoto(user1.photo.photo_big, provider);
                        return;
                    }
                    return;
                }
                if (NewProfileActivity.this.dialog_id != 0) {
                    TLRPC.Chat chat = MessagesController.getInstance(NewProfileActivity.this.currentAccount).getChat(Integer.valueOf((int) NewProfileActivity.this.dialog_id));
                    if (chat.photo != null && chat.photo.photo_big != null) {
                        PhotoViewer.getInstance().setParentActivity(NewProfileActivity.this.getParentActivity());
                        if (chat.photo.dc_id != 0) {
                            chat.photo.photo_big.dc_id = chat.photo.dc_id;
                        }
                        PhotoViewer.getInstance().openPhoto(chat.photo.photo_big, provider);
                    }
                }
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            return NewProfileActivity.this.rowCount;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int position) {
            if (position != NewProfileActivity.this.headerRow) {
                if (position != NewProfileActivity.this.notifyRow && position != NewProfileActivity.this.blockRow) {
                    if (position != NewProfileActivity.this.hubEmptyRow && position != NewProfileActivity.this.signEmptyRow && position != NewProfileActivity.this.headerEmptyRow && position != NewProfileActivity.this.sendToSelfEmptyRow && position != NewProfileActivity.this.addContactsEmptyRow && position != NewProfileActivity.this.encriptEmptyRow) {
                        if (position != NewProfileActivity.this.sendToSelfRow && position != NewProfileActivity.this.addContactsRow) {
                            if (position == NewProfileActivity.this.hubRow) {
                                return 8;
                            }
                            return 0;
                        }
                        return 4;
                    }
                    return 3;
                }
                return 2;
            }
            return 1;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void startCall(final TLRPC.User user) {
        List<String> list = new ArrayList<>();
        list.add(LocaleController.getString("menu_voice_chat", R.string.menu_voice_chat));
        list.add(LocaleController.getString("menu_video_chat", R.string.menu_video_chat));
        List<Integer> list1 = new ArrayList<>();
        list1.add(Integer.valueOf(R.drawable.menu_voice_call));
        list1.add(Integer.valueOf(R.drawable.menu_video_call));
        DialogCommonList dialogCommonList = new DialogCommonList(getParentActivity(), list, list1, Color.parseColor("#222222"), new DialogCommonList.RecyclerviewItemClickCallBack() { // from class: im.uwrkaxlmjj.ui.hui.chats.-$$Lambda$NewProfileActivity$yriPbcSdCeXc6YNRgDYPQtOLuxg
            @Override // im.uwrkaxlmjj.ui.dialogs.DialogCommonList.RecyclerviewItemClickCallBack
            public final void onRecyclerviewItemClick(int i) {
                this.f$0.lambda$startCall$11$NewProfileActivity(user, i);
            }
        }, 1);
        dialogCommonList.show();
    }

    public /* synthetic */ void lambda$startCall$11$NewProfileActivity(TLRPC.User user, int position) {
        if (position == 0) {
            if (ApplicationLoader.mbytAVideoCallBusy == 0) {
                if (user.mutual_contact) {
                    int currentConnectionState = ConnectionsManager.getInstance(this.currentAccount).getConnectionState();
                    if (currentConnectionState == 2 || currentConnectionState == 1) {
                        ToastUtils.show((CharSequence) LocaleController.getString("visual_call_no_network", R.string.visual_call_no_network));
                        return;
                    }
                    Intent intent = new Intent();
                    intent.setClass(getParentActivity(), VisualCallActivity.class);
                    intent.putExtra("CallType", 1);
                    ArrayList<Integer> ArrInputPeers = new ArrayList<>();
                    ArrInputPeers.add(Integer.valueOf(user.id));
                    intent.putExtra("ArrayUser", ArrInputPeers);
                    intent.putExtra("channel", new ArrayList());
                    getParentActivity().startActivity(intent);
                    return;
                }
                ToastUtils.show((CharSequence) LocaleController.getString("visual_call_no_friend_tip", R.string.visual_call_no_friend_tip));
                return;
            }
            ToastUtils.show((CharSequence) LocaleController.getString("visual_call_busing_tip", R.string.visual_call_busing_tip));
            return;
        }
        if (position == 1) {
            if (ApplicationLoader.mbytAVideoCallBusy == 0) {
                if (user.mutual_contact) {
                    int currentConnectionState2 = ConnectionsManager.getInstance(this.currentAccount).getConnectionState();
                    if (currentConnectionState2 == 2 || currentConnectionState2 == 1) {
                        ToastUtils.show((CharSequence) LocaleController.getString("visual_call_no_network", R.string.visual_call_no_network));
                        return;
                    }
                    Intent intent2 = new Intent();
                    intent2.setClass(getParentActivity(), VisualCallActivity.class);
                    intent2.putExtra("CallType", 2);
                    ArrayList<Integer> ArrInputPeers2 = new ArrayList<>();
                    ArrInputPeers2.add(Integer.valueOf(user.id));
                    intent2.putExtra("ArrayUser", ArrInputPeers2);
                    intent2.putExtra("channel", new ArrayList());
                    getParentActivity().startActivity(intent2);
                    return;
                }
                ToastUtils.show((CharSequence) LocaleController.getString("visual_call_no_friend_tip", R.string.visual_call_no_friend_tip));
                return;
            }
            ToastUtils.show((CharSequence) LocaleController.getString("visual_call_busing_tip", R.string.visual_call_busing_tip));
        }
    }
}
