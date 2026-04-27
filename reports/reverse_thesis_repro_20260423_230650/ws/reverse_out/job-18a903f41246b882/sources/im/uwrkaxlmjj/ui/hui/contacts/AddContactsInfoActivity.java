package im.uwrkaxlmjj.ui.hui.contacts;

import android.content.Context;
import android.content.DialogInterface;
import android.graphics.PorterDuff;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.text.TextUtils;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.TextView;
import butterknife.BindView;
import butterknife.OnClick;
import com.google.android.exoplayer2.trackselection.AdaptiveTrackSelection;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.UserObject;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.tgnet.TLRPCContacts;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.actionbar.ThemeDescription;
import im.uwrkaxlmjj.ui.actionbar.XAlertDialog;
import im.uwrkaxlmjj.ui.components.AvatarDrawable;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.hui.contacts.GreetEditActivity;
import im.uwrkaxlmjj.ui.hui.contacts.NoteAndGroupingEditActivity;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.FcSettingActivity;
import im.uwrkaxlmjj.ui.hui.wallet_public.utils.WalletDialogUtil;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import im.uwrkaxlmjj.ui.hviews.dialogs.XDialog;
import mpEIGo.juqQQs.esbSDO.R;
import org.json.JSONException;
import org.json.JSONObject;

/* JADX INFO: loaded from: classes5.dex */
public class AddContactsInfoActivity extends BaseFragment implements View.OnClickListener, NotificationCenter.NotificationCenterDelegate {
    public static final int FROM_APPLY = 7;
    public static final int FROM_APP_CODE_SEARCH = 4;
    public static final int FROM_BOOK = 6;
    public static final int FROM_GROUP = 2;
    public static final int FROM_NEARBY = 5;
    public static final int FROM_PHONE_SEARCH = 3;
    public static final int FROM_QR_CODE = 1;
    private int applyId;

    @BindView(R.attr.avatarImage)
    BackupImageView avatarImage;
    private int expire;

    @BindView(R.attr.flReplyLayout)
    FrameLayout flReplyLayout;
    private int fromType;
    private String greet;

    @BindView(R.attr.ivGender)
    ImageView ivGender;

    @BindView(R.attr.rlBioSettingView)
    RelativeLayout llBioSettingView;

    @BindView(R.attr.llInfoLayout)
    LinearLayout llInfoLayout;

    @BindView(R.attr.llOriginalView)
    LinearLayout llOriginalView;
    private Context mContext;

    @BindView(R.attr.mryNameView)
    MryTextView mryNameView;

    @BindView(R.attr.rcvReplyList)
    RecyclerListView rcvReplyList;
    private int reqState;

    @BindView(R.attr.tvAddContactStatus)
    TextView tvAddContactStatus;

    @BindView(R.attr.tvBioDesc)
    TextView tvBioDesc;

    @BindView(R.attr.tvBioText)
    TextView tvBioText;

    @BindView(R.attr.tvNoteSettingView)
    TextView tvNoteSettingView;

    @BindView(R.attr.tvOriginalDesc)
    TextView tvOriginalDesc;

    @BindView(R.attr.tvOriginalText)
    TextView tvOriginalText;

    @BindView(R.attr.tvReplyButton)
    TextView tvReplyButton;

    @BindView(R.attr.tvReplyText)
    TextView tvReplyText;

    @BindView(R.attr.tv_update_time)
    MryTextView tvUpdateTime;
    private TLRPC.User user;
    private TLRPCContacts.CL_userFull_v1 userFull;
    private int userGroupId;
    private String userGroupName;
    private String userNote;

    public AddContactsInfoActivity(Bundle args, TLRPC.User user) {
        super(args);
        this.userGroupId = -1;
        this.userNote = "";
        this.reqState = 0;
        this.user = user;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        if (this.arguments != null) {
            this.fromType = this.arguments.getInt("from_type", this.fromType);
            this.reqState = this.arguments.getInt("req_state", 0);
            this.applyId = this.arguments.getInt("apply_id", 0);
            this.expire = this.arguments.getInt("expire", 0);
            this.greet = this.arguments.getString("greet", "");
        }
        if (this.user == null) {
            return false;
        }
        TLRPC.UserFull full = MessagesController.getInstance(this.currentAccount).getUserFull(this.user.id);
        if (full instanceof TLRPCContacts.CL_userFull_v1) {
            this.userFull = (TLRPCContacts.CL_userFull_v1) full;
        }
        getMessagesController().loadFullUser(this.user, this.classGuid, true);
        getNotificationCenter().addObserver(this, NotificationCenter.userFullInfoDidLoad);
        return true;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.mContext = context;
        this.fragmentView = LayoutInflater.from(context).inflate(R.layout.activity_add_contact_info_layout, (ViewGroup) null, false);
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        useButterKnife();
        initActionBar();
        initViews();
        setViewData();
        return this.fragmentView;
    }

    private void initActionBar() {
        this.actionBar.setTitle(LocaleController.getString("PersonalInfo", R.string.PersonalInfo));
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setCastShadows(false);
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.hui.contacts.AddContactsInfoActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    AddContactsInfoActivity.this.finishFragment();
                    return;
                }
                if (id == 1) {
                    if (AddContactsInfoActivity.this.userFull != null && AddContactsInfoActivity.this.userFull.getExtendBean() != null) {
                        AddContactsInfoActivity.this.presentFragment(new FcSettingActivity(r0.user.id, AddContactsInfoActivity.this.userFull.getExtendBean().sex));
                    } else {
                        AddContactsInfoActivity.this.presentFragment(new FcSettingActivity(r0.user.id, 0));
                    }
                }
            }
        });
    }

    private void initViews() {
        this.avatarImage.setRoundRadius(AndroidUtilities.dp(7.5f));
        this.llInfoLayout.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), 0.0f, 0.0f, Theme.getColor(Theme.key_windowBackgroundWhite)));
        Drawable drawable = this.flReplyLayout.getBackground();
        drawable.setColorFilter(Theme.getColor(Theme.key_windowBackgroundGray), PorterDuff.Mode.SRC_IN);
        this.tvReplyText.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText));
        this.tvReplyButton.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlueText));
        this.tvNoteSettingView.setBackground(Theme.getSelectorDrawable(true));
        this.tvNoteSettingView.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
        this.llBioSettingView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
        this.tvBioDesc.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
        this.tvBioDesc.setText(LocaleController.getString("UserBio", R.string.UserBio));
        this.tvBioText.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText));
        this.llOriginalView.setBackground(Theme.createRoundRectDrawable(0.0f, 0.0f, AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
        this.tvOriginalDesc.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
        this.tvOriginalDesc.setText(LocaleController.getString("OriginalText", R.string.OriginalText));
        this.tvOriginalText.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText));
        this.tvAddContactStatus.setBackground(Theme.getRoundRectSelectorDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
        this.tvAddContactStatus.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlueText));
        int i = this.fromType;
        if (i == 1) {
            this.tvOriginalText.setText(LocaleController.getString("SharedbyQRCode", R.string.SharedbyQRCode));
            return;
        }
        if (i == 2) {
            this.tvOriginalText.setText(LocaleController.getString("ByGroup", R.string.ByGroup));
            return;
        }
        if (i == 3) {
            this.tvOriginalText.setText(LocaleController.getString("SearchedByPhone", R.string.SearchedByPhone));
            return;
        }
        if (i == 4) {
            this.tvOriginalText.setText(LocaleController.getString("SearchedByUsername", R.string.SearchedByUsername));
        } else if (i == 5) {
            this.tvOriginalText.setText(LocaleController.getString("ByNearby", R.string.ByNearby));
        } else if (i == 6) {
            this.tvOriginalText.setText(LocaleController.getString("ByPhoneBook", R.string.ByPhoneBook));
        }
    }

    @Override // android.view.View.OnClickListener
    @OnClick({R.attr.tvReplyButton, R.attr.tvNoteSettingView, R.attr.tvAddContactStatus})
    public void onClick(View view) {
        int id = view.getId();
        if (id == R.attr.tvAddContactStatus) {
            if (this.fromType == 7) {
                if (this.reqState == 0 && getConnectionsManager().getCurrentTime() <= this.expire) {
                    acceptApplyRequest(this.applyId, this.userGroupId, this.userNote);
                    return;
                }
                return;
            }
            jumpToEditGreetActivity();
            return;
        }
        if (id != R.attr.tvNoteSettingView) {
            if (id == R.attr.tvReplyButton) {
                jumpToReplyGreetActivity();
            }
        } else if (this.fromType != 7 || (this.reqState == 0 && getConnectionsManager().getCurrentTime() <= this.expire)) {
            jumpToEditUserNoteActivity();
        }
    }

    private void setViewData() {
        if (this.fromType == 7) {
            int i = this.reqState;
            if (i == 0) {
                if (getConnectionsManager().getCurrentTime() <= this.expire) {
                    this.tvAddContactStatus.setText(LocaleController.getString("AssentRequest", R.string.AssentRequest));
                } else {
                    this.tvAddContactStatus.setText(LocaleController.getString("RequestExpired", R.string.RequestExpired));
                }
            } else if (i == 1 || this.user.contact) {
                this.tvAddContactStatus.setText(LocaleController.getString("AddedContacts", R.string.AddedContacts));
            } else if (this.reqState == 2) {
                this.tvAddContactStatus.setText(LocaleController.getString("RequestExpired", R.string.RequestExpired));
            }
            this.tvAddContactStatus.setTextColor((this.reqState != 0 || getConnectionsManager().getCurrentTime() > this.expire) ? -4737097 : -14250753);
        } else {
            this.tvAddContactStatus.setText(LocaleController.getString("AddFriends", R.string.AddFriends));
        }
        TLRPCContacts.CL_userFull_v1 cL_userFull_v1 = this.userFull;
        if (cL_userFull_v1 != null) {
            if (cL_userFull_v1.user != null) {
                this.user = this.userFull.user;
                getMessagesController().putUser(this.user, false);
            }
            this.tvBioText.setText(TextUtils.isEmpty(this.userFull.about) ? LocaleController.getString("BioNothing", R.string.BioNothing) : this.userFull.about);
            boolean zIsEmpty = TextUtils.isEmpty(this.userFull.extend.data);
            int i2 = R.id.ic_female;
            if (!zIsEmpty) {
                try {
                    JSONObject json = new JSONObject(this.userFull.extend.data);
                    this.ivGender.setImageResource(json.getInt("sex") == 1 ? R.id.ic_male : R.id.ic_female);
                    if (this.fromType == 7) {
                        int source = json.getInt("source");
                        if (source == 1) {
                            this.tvOriginalText.setText(LocaleController.getString("SharedbyQRCode", R.string.SharedbyQRCode));
                        } else if (source == 2) {
                            this.tvOriginalText.setText(LocaleController.getString("ByGroup", R.string.ByGroup));
                        } else if (source == 3) {
                            this.tvOriginalText.setText(LocaleController.getString("SearchedByPhone", R.string.SearchedByPhone));
                        } else if (source == 4) {
                            this.tvOriginalText.setText(LocaleController.getString("SearchedByUsername", R.string.SearchedByUsername));
                        } else if (source == 5) {
                            this.tvOriginalText.setText(LocaleController.getString("ByNearby", R.string.ByNearby));
                        } else if (source == 6) {
                            this.tvOriginalText.setText(LocaleController.getString("ByPhoneBook", R.string.ByPhoneBook));
                        }
                    }
                } catch (JSONException e) {
                    e.printStackTrace();
                }
            }
            if (this.userFull.getExtendBean() != null) {
                int sex = this.userFull.getExtendBean().sex;
                ImageView imageView = this.ivGender;
                if (sex == 1) {
                    i2 = R.id.ic_male;
                } else if (sex != 2) {
                    i2 = 0;
                }
                imageView.setImageResource(i2);
                if (sex != 1 && sex != 2) {
                    this.ivGender.setVisibility(8);
                } else {
                    this.ivGender.setVisibility(0);
                }
            }
        }
        if (this.user != null) {
            AvatarDrawable avatarDrawable = new AvatarDrawable();
            avatarDrawable.setTextSize(AndroidUtilities.dp(16.0f));
            avatarDrawable.setInfo(this.user);
            this.mryNameView.setText(UserObject.getName(this.user));
            this.avatarImage.getImageReceiver().setCurrentAccount(this.currentAccount);
            this.avatarImage.setImage(ImageLocation.getForUser(this.user, false), "50_50", avatarDrawable, this.user);
            this.tvUpdateTime.setText(LocaleController.formatUserStatus(this.currentAccount, this.user));
            this.flReplyLayout.setVisibility(this.fromType == 7 ? 0 : 8);
            this.tvReplyText.setText(this.user.first_name + ": " + this.greet);
        }
    }

    private void acceptApplyRequest(final int applyId, final int groupId, final String firstName) {
        XDialog.Builder builder = new XDialog.Builder(getParentActivity());
        builder.setMessage(LocaleController.getString("AcceptContactTip", R.string.AcceptContactTip));
        builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
        builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$AddContactsInfoActivity$k68GLqalckmKGV3et-Owv9UWKBo
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                this.f$0.lambda$acceptApplyRequest$4$AddContactsInfoActivity(applyId, groupId, firstName, dialogInterface, i);
            }
        });
        XDialog xDialog = builder.create();
        showDialog(xDialog);
    }

    public /* synthetic */ void lambda$acceptApplyRequest$4$AddContactsInfoActivity(final int applyId, int groupId, String firstName, DialogInterface dialog, int which) {
        final XAlertDialog progressDialog = new XAlertDialog(getParentActivity(), 4);
        progressDialog.setLoadingText(LocaleController.getString(R.string.ApplyAdding));
        TLRPCContacts.AcceptContactApply req = new TLRPCContacts.AcceptContactApply();
        req.apply_id = applyId;
        req.group_id = Math.max(groupId, 0);
        req.first_name = firstName;
        req.last_name = "";
        ConnectionsManager connectionsManager = getConnectionsManager();
        final int reqId = getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$AddContactsInfoActivity$0Uo8pyHmHt9j5Y_23DIptUw_C58
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) throws Exception {
                this.f$0.lambda$null$2$AddContactsInfoActivity(progressDialog, applyId, tLObject, tL_error);
            }
        });
        connectionsManager.bindRequestToGuid(reqId, this.classGuid);
        progressDialog.setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$AddContactsInfoActivity$VpyVxa0qQeukfSoRb_OriRgNcTE
            @Override // android.content.DialogInterface.OnCancelListener
            public final void onCancel(DialogInterface dialogInterface) {
                this.f$0.lambda$null$3$AddContactsInfoActivity(reqId, dialogInterface);
            }
        });
        progressDialog.show();
    }

    public /* synthetic */ void lambda$null$2$AddContactsInfoActivity(final XAlertDialog progressDialog, final int applyId, TLObject response, TLRPC.TL_error error) throws Exception {
        if (error != null) {
            progressDialog.dismiss();
            ToastUtils.show((CharSequence) ContactsUtils.getAboutContactsErrText(error));
            return;
        }
        TLRPC.Updates res = (TLRPC.Updates) response;
        getMessagesController().processUpdates(res, false);
        TLRPCContacts.ContactApplyInfo info = new TLRPCContacts.ContactApplyInfo();
        info.id = applyId;
        info.state = 1;
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$AddContactsInfoActivity$lyusR5PE-Cdin-685KILPVGgVus
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$1$AddContactsInfoActivity(applyId, progressDialog);
            }
        });
    }

    public /* synthetic */ void lambda$null$1$AddContactsInfoActivity(int applyId, final XAlertDialog progressDialog) {
        this.reqState = 1;
        setViewData();
        getNotificationCenter().postNotificationName(NotificationCenter.contactApplyUpdateState, Integer.valueOf(applyId), Integer.valueOf(this.reqState));
        finishFragment();
        progressDialog.setLoadingImage(this.mContext.getResources().getDrawable(R.id.ic_apply_send_done), AndroidUtilities.dp(30.0f), AndroidUtilities.dp(20.0f));
        progressDialog.setLoadingText(LocaleController.getString(R.string.AddedContacts));
        this.fragmentView.postDelayed(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$AddContactsInfoActivity$gMu8pBa3pnl8orzFn949Bd7Mr6Q
            @Override // java.lang.Runnable
            public final void run() {
                progressDialog.dismiss();
            }
        }, AdaptiveTrackSelection.DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS);
    }

    public /* synthetic */ void lambda$null$3$AddContactsInfoActivity(int reqId, DialogInterface hintDialog) {
        getConnectionsManager().cancelRequest(reqId, true);
    }

    private void jumpToEditGreetActivity() {
        Bundle bundle = new Bundle();
        bundle.putInt("type", 0);
        GreetEditActivity greetEditActivity = new GreetEditActivity(bundle);
        greetEditActivity.setDelegate(new GreetEditActivity.GreetEditDelegate() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$AddContactsInfoActivity$Pn5qErwUfOW_8yfxEZ9SRGXpwAA
            @Override // im.uwrkaxlmjj.ui.hui.contacts.GreetEditActivity.GreetEditDelegate
            public final void onFinish(String str) {
                this.f$0.startContactApply(str);
            }
        });
        presentFragment(greetEditActivity);
    }

    private void jumpToEditUserNoteActivity() {
        Bundle bundle = new Bundle();
        bundle.putInt("user_id", this.user.id);
        bundle.putInt("groupId", this.userGroupId);
        bundle.putString("groupName", this.userGroupName);
        bundle.putString("userNote", this.userNote);
        bundle.putInt("type", 1);
        NoteAndGroupingEditActivity contactAddInfoEditActivity = new NoteAndGroupingEditActivity(bundle);
        contactAddInfoEditActivity.setDelegate(new NoteAndGroupingEditActivity.AddInfoDelegate() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$AddContactsInfoActivity$NPiWGSbLPo-5da2fI4nAyRpiZDM
            @Override // im.uwrkaxlmjj.ui.hui.contacts.NoteAndGroupingEditActivity.AddInfoDelegate
            public final void onFinish(int i, String str, String str2) {
                this.f$0.lambda$jumpToEditUserNoteActivity$5$AddContactsInfoActivity(i, str, str2);
            }
        });
        presentFragment(contactAddInfoEditActivity);
    }

    public /* synthetic */ void lambda$jumpToEditUserNoteActivity$5$AddContactsInfoActivity(int groupId, String groupName, String note) {
        this.userGroupId = groupId;
        this.userGroupName = groupName;
        this.userNote = note;
        if (!TextUtils.isEmpty(note)) {
            this.mryNameView.setText(this.userNote);
        } else {
            this.mryNameView.setText(UserObject.getName(this.user));
        }
    }

    private void jumpToReplyGreetActivity() {
        Bundle bundle = new Bundle();
        bundle.putInt("type", 1);
        final GreetEditActivity greetEditActivity = new GreetEditActivity(bundle);
        this.tvReplyButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$AddContactsInfoActivity$kfciGAh-nhgFoU9a7eeHT9YByco
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$jumpToReplyGreetActivity$6$AddContactsInfoActivity(greetEditActivity, view);
            }
        });
    }

    public /* synthetic */ void lambda$jumpToReplyGreetActivity$6$AddContactsInfoActivity(GreetEditActivity greetEditActivity, View v) {
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
        req.first_name = this.userNote;
        req.last_name = "";
        req.greet = greet;
        req.group_id = Math.max(this.userGroupId, 0);
        ConnectionsManager connectionsManager = getConnectionsManager();
        final int reqId = getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$AddContactsInfoActivity$pemoJ51d3Cxl-QzW6jpsTtqfnKs
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$startContactApply$9$AddContactsInfoActivity(progressDialog, tLObject, tL_error);
            }
        });
        connectionsManager.bindRequestToGuid(reqId, this.classGuid);
        progressDialog.setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$AddContactsInfoActivity$HIQ1_5ZtgrhM0dZkeBFORX107lI
            @Override // android.content.DialogInterface.OnCancelListener
            public final void onCancel(DialogInterface dialogInterface) {
                this.f$0.lambda$startContactApply$10$AddContactsInfoActivity(reqId, dialogInterface);
            }
        });
        progressDialog.show();
    }

    public /* synthetic */ void lambda$startContactApply$9$AddContactsInfoActivity(final XAlertDialog progressDialog, final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$AddContactsInfoActivity$S_XBMj_wMVo9NqM3nPu1fTm2XDI
            @Override // java.lang.Runnable
            public final void run() throws Exception {
                this.f$0.lambda$null$8$AddContactsInfoActivity(error, progressDialog, response);
            }
        });
    }

    public /* synthetic */ void lambda$null$8$AddContactsInfoActivity(TLRPC.TL_error error, final XAlertDialog progressDialog, TLObject response) throws Exception {
        TLRPC.TL_updates updates;
        if (error != null) {
            if (this.fromType == 5 && TextUtils.isEmpty(error.text) && "USER_ADDCONTACT_TOMANY_BYDAY".equals(error.text)) {
                WalletDialogUtil.showConfirmBtnWalletDialog(this, LocaleController.getString(R.string.ContactsAddLimitByDay));
                return;
            } else {
                progressDialog.dismiss();
                ToastUtils.show((CharSequence) ContactsUtils.getAboutContactsErrText(error));
                return;
            }
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
        this.fragmentView.postDelayed(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$AddContactsInfoActivity$edVGBjyJ8i8VuTcOZ0YHoqiCLjA
            @Override // java.lang.Runnable
            public final void run() {
                progressDialog.dismiss();
            }
        }, AdaptiveTrackSelection.DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS);
    }

    public /* synthetic */ void lambda$startContactApply$10$AddContactsInfoActivity(int reqId, DialogInterface dialog) {
        getConnectionsManager().cancelRequest(reqId, true);
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        if (id == NotificationCenter.userFullInfoDidLoad) {
            int userId = ((Integer) args[0]).intValue();
            TLRPC.User user = this.user;
            if (user != null && userId == user.id && (args[1] instanceof TLRPCContacts.CL_userFull_v1)) {
                this.userFull = (TLRPCContacts.CL_userFull_v1) args[1];
                setViewData();
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        getNotificationCenter().removeObserver(this, NotificationCenter.userFullInfoDidLoad);
        super.onFragmentDestroy();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public ThemeDescription[] getThemeDescriptions() {
        return new ThemeDescription[]{new ThemeDescription(this.llInfoLayout, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_windowBackgroundWhite), new ThemeDescription(this.tvReplyText, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteGrayText4), new ThemeDescription(this.tvReplyButton, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_chat_attachUnactiveTab), new ThemeDescription(this.tvNoteSettingView, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_windowBackgroundWhite), new ThemeDescription(this.tvNoteSettingView, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.llBioSettingView, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_windowBackgroundWhite), new ThemeDescription(this.tvBioDesc, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.tvBioText, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteGrayText4), new ThemeDescription(this.llOriginalView, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_windowBackgroundWhite), new ThemeDescription(this.tvOriginalDesc, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.tvOriginalText, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteGrayText4), new ThemeDescription(this.tvAddContactStatus, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_windowBackgroundWhite), new ThemeDescription(this.tvAddContactStatus, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteBlueText)};
    }
}
