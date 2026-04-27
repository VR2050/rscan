package im.uwrkaxlmjj.ui.hui.mine;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.graphics.Bitmap;
import android.os.Bundle;
import android.text.TextUtils;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import com.bigkoo.pickerview.listener.OnTimeSelectListener;
import com.blankj.utilcode.util.TimeUtils;
import com.king.zxing.util.CodeUtils;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.FileLoader;
import im.uwrkaxlmjj.messenger.ImageLoader;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.MessagesStorage;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.SendMessagesHelper;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.phoneformat.PhoneFormat;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.tgnet.TLRPCContacts;
import im.uwrkaxlmjj.tgnet.TLRPCLogin;
import im.uwrkaxlmjj.ui.ChangeBioActivity;
import im.uwrkaxlmjj.ui.ChangeNameActivity;
import im.uwrkaxlmjj.ui.ChangeUsernameActivity;
import im.uwrkaxlmjj.ui.PhotoViewer;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.AvatarDrawable;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.components.ImageUpdater;
import im.uwrkaxlmjj.ui.components.RadialProgressView;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.dialogs.TimeWheelPickerDialog;
import im.uwrkaxlmjj.ui.hui.discovery.ActionIntroActivity;
import im.uwrkaxlmjj.ui.hui.login.ChangePersonalInformationActivity;
import im.uwrkaxlmjj.ui.hui.login.LoginContronllerActivity;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import mpEIGo.juqQQs.esbSDO.R;
import org.slf4j.Marker;

/* JADX INFO: loaded from: classes5.dex */
@Deprecated
public class UserInfoActivity extends BaseFragment implements View.OnClickListener, NotificationCenter.NotificationCenterDelegate, ImageUpdater.ImageUpdaterDelegate, View.OnLongClickListener {
    private static final int DONE_BUTTON = 1;
    private TLRPC.FileLocation avatar;
    private AnimatorSet avatarAnimation;
    private TLRPC.FileLocation avatarBig;
    private AvatarDrawable avatarDrawable;
    private BackupImageView avatarImage;
    private ImageView avatarOverly;
    private RadialProgressView avatarProgressView;
    private FrameLayout flQRCode;
    private ImageUpdater imageUpdater;
    private ImageView ivCamera;
    private LinearLayout llChangeBirthday;
    private LinearLayout llChangeGender;
    private LinearLayout llChangeNumber;
    private LinearLayout llUserInfoLayout;
    private LinearLayout llUsername;
    private Context mContext;
    private TimeWheelPickerDialog.Builder mTimePickerBuilder;
    private TLRPCContacts.CL_userFull_v1 mUserFull;
    private boolean mblnUpdateFromInit = true;
    private boolean requesting;
    private TextView tvAddAccount;
    private TextView tvAvatarAndNameDesc;
    private TextView tvBioDesc;
    private TextView tvBioText;
    private TextView tvBirthday;
    private TextView tvChangeBirthday;
    private TextView tvChangeGender;
    private TextView tvChangeNumber;
    private TextView tvChangeUsername;
    private TextView tvGender;
    private TextView tvLogout;
    private TextView tvName;
    private TextView tvQRCode;
    private TextView tvUsername;
    private TextView tvUserphone;
    private TLRPC.UserFull userInfo;

    @Override // im.uwrkaxlmjj.ui.components.ImageUpdater.ImageUpdaterDelegate
    public /* synthetic */ void didSelectPhotos(ArrayList<SendMessagesHelper.SendingMediaInfo> arrayList, boolean z, int i) {
        ImageUpdater.ImageUpdaterDelegate.CC.$default$didSelectPhotos(this, arrayList, z, i);
    }

    @Override // im.uwrkaxlmjj.ui.components.ImageUpdater.ImageUpdaterDelegate
    public /* synthetic */ String getInitialSearchString() {
        return ImageUpdater.ImageUpdaterDelegate.CC.$default$getInitialSearchString(this);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        super.onFragmentCreate();
        ImageUpdater imageUpdater = new ImageUpdater();
        this.imageUpdater = imageUpdater;
        imageUpdater.parentFragment = this;
        this.imageUpdater.delegate = this;
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.updateInterfaces);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.userFullInfoDidLoad);
        this.userInfo = MessagesController.getInstance(this.currentAccount).getUserFull(UserConfig.getInstance(this.currentAccount).getClientUserId());
        MessagesController.getInstance(this.currentAccount).loadUserInfo(UserConfig.getInstance(this.currentAccount).getCurrentUser(), true, this.classGuid);
        return true;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        super.onFragmentDestroy();
        BackupImageView backupImageView = this.avatarImage;
        if (backupImageView != null) {
            backupImageView.setImageDrawable(null);
        }
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.updateInterfaces);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.userFullInfoDidLoad);
        this.imageUpdater.clear();
        this.mTimePickerBuilder = null;
        this.mUserFull = null;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.mContext = context;
        this.fragmentView = LayoutInflater.from(context).inflate(R.layout.activity_user_info_layout, (ViewGroup) null, false);
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        initActionBar();
        initUserInfo();
        initUsername();
        initPhoneNumber();
        initQRCode();
        initBirthday();
        initGender();
        initOther();
        initData();
        updateUserData();
        return this.fragmentView;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onActivityResultFragment(int requestCode, int resultCode, Intent data) throws FileNotFoundException {
        this.imageUpdater.onActivityResult(requestCode, resultCode, data);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void saveSelfArgs(Bundle args) {
        ImageUpdater imageUpdater = this.imageUpdater;
        if (imageUpdater != null && imageUpdater.currentPicturePath != null) {
            args.putString("path", this.imageUpdater.currentPicturePath);
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void restoreSelfArgs(Bundle args) {
        ImageUpdater imageUpdater = this.imageUpdater;
        if (imageUpdater != null) {
            imageUpdater.currentPicturePath = args.getString("path");
        }
    }

    private void initActionBar() {
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setAllowOverlayTitle(true);
        this.actionBar.setTitle(LocaleController.getString("PersonalResource", R.string.PersonalResource));
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.hui.mine.UserInfoActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    UserInfoActivity.this.finishFragment();
                }
            }
        });
    }

    private void initUserInfo() {
        LinearLayout linearLayout = (LinearLayout) this.fragmentView.findViewById(R.attr.llInfoLayout);
        this.llUserInfoLayout = linearLayout;
        linearLayout.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
        BackupImageView backupImageView = (BackupImageView) this.fragmentView.findViewById(R.attr.avatarImage);
        this.avatarImage = backupImageView;
        backupImageView.setRoundRadius(AndroidUtilities.dp(7.5f));
        this.avatarImage.setContentDescription(LocaleController.getString("AccDescrProfilePicture", R.string.AccDescrProfilePicture));
        this.avatarOverly = (ImageView) this.fragmentView.findViewById(R.attr.avatarOverly);
        RadialProgressView radialProgressView = (RadialProgressView) this.fragmentView.findViewById(R.attr.rpvAvatar);
        this.avatarProgressView = radialProgressView;
        radialProgressView.setVisibility(4);
        this.ivCamera = (ImageView) this.fragmentView.findViewById(R.attr.iv_camera);
        this.tvName = (TextView) this.fragmentView.findViewById(R.attr.tvName);
        this.tvBioText = (TextView) this.fragmentView.findViewById(R.attr.tvBioText);
        this.tvAvatarAndNameDesc = (TextView) this.fragmentView.findViewById(R.attr.tvAvatarAndNameDesc);
        this.tvBioDesc = (TextView) this.fragmentView.findViewById(R.attr.tvBioDesc);
        this.tvName.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
        this.tvName.setHintTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteHintText));
        this.tvBioText.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
        this.tvBioText.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
        this.tvAvatarAndNameDesc.setText(LocaleController.getString("NameAndAvatar", R.string.NameAndAvatar));
        this.tvBioDesc.setText(LocaleController.getString("NameAndAvatar", R.string.BioText));
        this.llUserInfoLayout.setOnClickListener(this);
        this.avatarImage.setOnClickListener(this);
        this.tvBioText.setOnClickListener(this);
        LinearLayout llUserInfoLayout = (LinearLayout) this.fragmentView.findViewById(R.attr.llUserInfoLayout);
        llUserInfoLayout.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
    }

    private void initPhoneNumber() {
        this.llChangeNumber = (LinearLayout) this.fragmentView.findViewById(R.attr.llChangeNumber);
        this.tvChangeNumber = (TextView) this.fragmentView.findViewById(R.attr.tvChangeNumber);
        this.tvUserphone = (TextView) this.fragmentView.findViewById(R.attr.tvPhoneNumber);
        this.tvChangeNumber.setText(LocaleController.getString("ChangeNumber", R.string.ChangeNumber));
        this.tvChangeNumber.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
        this.llChangeNumber.setOnClickListener(this);
    }

    private void initUsername() {
        this.tvChangeUsername = (TextView) this.fragmentView.findViewById(R.attr.tvChangeUsername);
        this.tvUsername = (TextView) this.fragmentView.findViewById(R.attr.tvUsername);
        this.llUsername = (LinearLayout) this.fragmentView.findViewById(R.attr.llUsername);
        this.tvChangeUsername.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
        this.tvChangeUsername.setText(LocaleController.getString("AppNameCode2", R.string.AppNameCode2));
        this.llUsername.setOnClickListener(this);
        this.llUsername.setOnLongClickListener(this);
    }

    private void initQRCode() {
        this.flQRCode = (FrameLayout) this.fragmentView.findViewById(R.attr.flQRCode);
        TextView textView = (TextView) this.fragmentView.findViewById(R.attr.tvQRCode);
        this.tvQRCode = textView;
        textView.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
        this.tvQRCode.setText(LocaleController.getString("MyQRCode", R.string.MyQRCode));
        this.flQRCode.setOnClickListener(this);
    }

    private void initBirthday() {
        this.llChangeBirthday = (LinearLayout) this.fragmentView.findViewById(R.attr.llChangeBirthday);
        this.tvChangeBirthday = (TextView) this.fragmentView.findViewById(R.attr.tvChangeBirthday);
        this.tvBirthday = (TextView) this.fragmentView.findViewById(R.attr.tvBirthday);
        this.tvChangeBirthday.setText(LocaleController.getString("Birthday", R.string.Birthday));
        this.tvChangeBirthday.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
        this.llChangeBirthday.setOnClickListener(this);
    }

    private void initGender() {
        this.llChangeGender = (LinearLayout) this.fragmentView.findViewById(R.attr.llChangeGender);
        this.tvChangeGender = (TextView) this.fragmentView.findViewById(R.attr.tvChangeGender);
        this.tvGender = (TextView) this.fragmentView.findViewById(R.attr.tvGender);
        this.tvChangeGender.setText(LocaleController.getString("PassportGender", R.string.PassportGender));
        this.tvChangeGender.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        super.onResume();
        initData();
    }

    private void initData() {
        String value;
        String value2;
        TLRPC.User user = UserConfig.getInstance(this.currentAccount).getCurrentUser();
        if (user != null && user.phone != null && user.phone.length() != 0) {
            value = PhoneFormat.getInstance().format(Marker.ANY_NON_NULL_MARKER + user.phone);
        } else {
            value = LocaleController.getString("NumberUnknown", R.string.NumberUnknown);
        }
        this.tvUserphone.setText(value);
        if (user != null && !TextUtils.isEmpty(user.username)) {
            value2 = user.username;
        } else {
            value2 = LocaleController.getString("UsernameEmpty", R.string.UsernameEmpty);
        }
        this.tvUsername.setText(value2);
        TLRPC.UserFull userFull = this.userInfo;
        if (userFull == null || !TextUtils.isEmpty(userFull.about)) {
            TLRPC.UserFull userFull2 = this.userInfo;
            String value3 = userFull2 == null ? LocaleController.getString("Loading", R.string.Loading) : userFull2.about;
            this.tvBioText.setText(value3);
        } else {
            this.tvBioText.setText(LocaleController.getString("UserBio", R.string.UserBio));
        }
        getFullUser();
    }

    private void initExtraUserInfoData(TLRPCContacts.CL_userFull_v1_Bean extend) {
        if (extend.sex == 1) {
            this.tvGender.setText(LocaleController.getString("PassportMale", R.string.PassportMale));
        } else if (extend.sex == 2) {
            this.tvGender.setText(LocaleController.getString("PassportMale", R.string.PassportFemale));
        }
        if (extend.birthday != 0) {
            this.tvBirthday.setText(TimeUtils.millis2String(((long) extend.birthday) * 1000, "yyyy-MM-dd"));
        }
    }

    private void initOther() {
        this.tvAddAccount = (TextView) this.fragmentView.findViewById(R.attr.tvAddAccount);
        this.tvLogout = (TextView) this.fragmentView.findViewById(R.attr.tvLogout);
        this.tvAddAccount.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
        this.tvAddAccount.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
        this.tvAddAccount.setText(LocaleController.getString("AddAccount", R.string.AddAccount));
        this.tvLogout.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
        this.tvLogout.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteRedText5));
        this.tvLogout.setText(LocaleController.getString("LogOut", R.string.LogOut));
        this.tvLogout.setOnClickListener(this);
        this.tvAddAccount.setOnClickListener(this);
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        if (id == NotificationCenter.updateInterfaces) {
            int mask = ((Integer) args[0]).intValue();
            if ((mask & 2) != 0 || (mask & 1) != 0) {
                updateUserData();
                return;
            }
            return;
        }
        if (id == NotificationCenter.userFullInfoDidLoad) {
            Integer uid = (Integer) args[0];
            if (uid.intValue() == UserConfig.getInstance(this.currentAccount).getClientUserId()) {
                TLRPC.UserFull userFull = (TLRPC.UserFull) args[1];
                this.userInfo = userFull;
                if (userFull == null || !TextUtils.isEmpty(userFull.about)) {
                    TLRPC.UserFull userFull2 = this.userInfo;
                    String value = userFull2 == null ? LocaleController.getString("Loading", R.string.Loading) : userFull2.about;
                    this.tvBioText.setText(value);
                    return;
                }
                this.tvBioText.setText(LocaleController.getString("UserBio", R.string.UserBio));
            }
        }
    }

    private void updateUserData() {
        TLRPC.User user = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(UserConfig.getInstance(this.currentAccount).getClientUserId()));
        if (user == null) {
            return;
        }
        TLRPC.FileLocation photoBig = null;
        if (user.photo != null) {
            photoBig = user.photo.photo_big;
        }
        AvatarDrawable avatarDrawable = new AvatarDrawable(user, true);
        this.avatarDrawable = avatarDrawable;
        avatarDrawable.setColor(Theme.getColor(Theme.key_avatar_backgroundInProfileBlue));
        BackupImageView backupImageView = this.avatarImage;
        if (backupImageView != null) {
            backupImageView.setImage(ImageLocation.getForUser(user, false), "50_50", this.avatarDrawable, user);
            this.avatarImage.getImageReceiver().setVisible(!PhotoViewer.isShowingImage(photoBig), false);
            this.tvName.setText(user.first_name);
            this.avatarImage.getImageReceiver().setVisible(true ^ PhotoViewer.isShowingImage(photoBig), false);
            if ((user.photo instanceof TLRPC.TL_userProfilePhoto) && !this.mblnUpdateFromInit) {
                saveImage();
            }
            this.mblnUpdateFromInit = false;
        }
    }

    private void saveImage() {
        new Thread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$UserInfoActivity$gZrrmxrxPOEflnCgUsa5rrxwkpU
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$saveImage$0$UserInfoActivity();
            }
        }).start();
    }

    public /* synthetic */ void lambda$saveImage$0$UserInfoActivity() {
        while (this.avatarImage.getImageReceiver().getBitmap() == null) {
            try {
                Thread.sleep(10L);
            } catch (Exception e) {
                e.printStackTrace();
                return;
            }
        }
        Bitmap bitmap = this.avatarImage.getImageReceiver().getBitmap();
        File file = new File(AndroidUtilities.getCacheDir().getPath() + File.separator + "user_avatar.jpg");
        if (file.exists()) {
            file.delete();
        }
        FileOutputStream out = new FileOutputStream(file);
        bitmap.compress(Bitmap.CompressFormat.JPEG, 100, out);
        out.flush();
        out.close();
    }

    @Override // android.view.View.OnClickListener
    public void onClick(View v) {
        switch (v.getId()) {
            case R.attr.avatarImage /* 2131296378 */:
                TLRPC.User user = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(UserConfig.getInstance(this.currentAccount).getClientUserId()));
                if (user == null) {
                    user = UserConfig.getInstance(this.currentAccount).getCurrentUser();
                }
                if (user != null) {
                    this.imageUpdater.openMenu((user.photo == null || user.photo.photo_big == null || (user.photo instanceof TLRPC.TL_userProfilePhotoEmpty)) ? false : true, new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$UserInfoActivity$Y0rj2dIskj6SG8w-c80RmWSPQCM
                        @Override // java.lang.Runnable
                        public final void run() {
                            this.f$0.lambda$onClick$3$UserInfoActivity();
                        }
                    });
                    break;
                }
                break;
            case R.attr.flQRCode /* 2131296623 */:
                QrCodeActivity qrCodeActivity = new QrCodeActivity(getUserConfig().getClientUserId());
                presentFragment(qrCodeActivity);
                break;
            case R.attr.llChangeBirthday /* 2131296898 */:
                AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
                builder.setTitle(LocaleController.getString(R.string.AppName));
                builder.setMessage(LocaleController.getString(R.string.UserBirthOnlyCanModifyOnceContuine));
                builder.setNegativeButton(LocaleController.getString(R.string.Cancel), null);
                builder.setPositiveButton(LocaleController.getString(R.string.Confirm), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$UserInfoActivity$iHQau9DsLK3Jkp2rbFlypedZnu4
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i) {
                        this.f$0.lambda$onClick$4$UserInfoActivity(dialogInterface, i);
                    }
                });
                showDialog(builder.create());
                break;
            case R.attr.llChangeNumber /* 2131296900 */:
                presentFragment(new ActionIntroActivity(3));
                break;
            case R.attr.llInfoLayout /* 2131296909 */:
                presentFragment(new ChangeNameActivity());
                break;
            case R.attr.llUsername /* 2131296921 */:
                AlertDialog.Builder ub = new AlertDialog.Builder(getParentActivity());
                ub.setTitle(LocaleController.getString(R.string.AppName));
                ub.setMessage(LocaleController.getString(R.string.ChangeAppNameCodeTips));
                ub.setNegativeButton(LocaleController.getString(R.string.Cancel), null);
                ub.setPositiveButton(LocaleController.getString(R.string.Modify), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$UserInfoActivity$EPQDsmHg04Kis74TkMAJDPMFHI4
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i) {
                        this.f$0.lambda$onClick$2$UserInfoActivity(dialogInterface, i);
                    }
                });
                showDialog(ub.create());
                break;
            case R.attr.tvAddAccount /* 2131297437 */:
                if (ApplicationLoader.mbytAVideoCallBusy == 0) {
                    int freeAccount = -1;
                    int a = 0;
                    while (true) {
                        if (a < 3) {
                            if (UserConfig.getInstance(a).isClientActivated()) {
                                a++;
                            } else {
                                freeAccount = a;
                            }
                        }
                    }
                    if (freeAccount >= 0) {
                        presentFragment(new LoginContronllerActivity(freeAccount));
                    }
                } else {
                    ToastUtils.show((CharSequence) LocaleController.getString(R.string.visual_call_stop_add_account));
                }
                break;
            case R.attr.tvBioText /* 2131297457 */:
                if (this.userInfo != null) {
                    presentFragment(new ChangeBioActivity());
                }
                break;
            case R.attr.tvLogout /* 2131297539 */:
                if (getParentActivity() != null) {
                    if (ApplicationLoader.mbytAVideoCallBusy == 0) {
                        AlertDialog.Builder builder2 = new AlertDialog.Builder(getParentActivity());
                        builder2.setMessage(LocaleController.getString("AreYouSureLogout", R.string.AreYouSureLogout));
                        builder2.setTitle(LocaleController.getString("AppName", R.string.AppName));
                        builder2.setPositiveButton(LocaleController.getString("OK", R.string.OK), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$UserInfoActivity$Eu3095x9Buqjv8LCfcpXdbPx5Zw
                            @Override // android.content.DialogInterface.OnClickListener
                            public final void onClick(DialogInterface dialogInterface, int i) {
                                this.f$0.lambda$onClick$1$UserInfoActivity(dialogInterface, i);
                            }
                        });
                        builder2.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
                        showDialog(builder2.create());
                    } else {
                        ToastUtils.show((CharSequence) LocaleController.getString(R.string.visual_call_stop_login_out));
                    }
                    break;
                }
                break;
        }
    }

    public /* synthetic */ void lambda$onClick$1$UserInfoActivity(DialogInterface dialogInterface, int i) {
        MessagesController.getInstance(this.currentAccount).performLogout(1);
    }

    public /* synthetic */ void lambda$onClick$2$UserInfoActivity(DialogInterface dialog, int which) {
        presentFragment(new ChangeUsernameActivity());
    }

    public /* synthetic */ void lambda$onClick$3$UserInfoActivity() {
        MessagesController.getInstance(this.currentAccount).deleteUserPhoto(null);
    }

    public /* synthetic */ void lambda$onClick$4$UserInfoActivity(DialogInterface dialog, int which) {
        showSelectBirthDialog();
    }

    @Override // android.view.View.OnLongClickListener
    public boolean onLongClick(View v) {
        TLRPC.UserFull userFull;
        if (v.getId() == R.attr.llUsername && (userFull = this.userInfo) != null && userFull.user != null && !TextUtils.isEmpty(this.userInfo.user.username)) {
            AndroidUtilities.addToClipboard("@" + this.userInfo.user.username);
            ToastUtils.show(R.string.TextCopied);
            return true;
        }
        return false;
    }

    private void showAvatarProgress(final boolean show, boolean animated) {
        if (this.avatarOverly == null) {
            return;
        }
        AnimatorSet animatorSet = this.avatarAnimation;
        if (animatorSet != null) {
            animatorSet.cancel();
            this.avatarAnimation = null;
        }
        if (animated) {
            this.avatarAnimation = new AnimatorSet();
            if (show) {
                this.avatarProgressView.setVisibility(0);
                this.ivCamera.setVisibility(8);
            }
            this.avatarAnimation.setDuration(180L);
            this.avatarAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.hui.mine.UserInfoActivity.2
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animation) {
                    if (UserInfoActivity.this.avatarAnimation == null) {
                        return;
                    }
                    if (!show) {
                        UserInfoActivity.this.avatarProgressView.setVisibility(4);
                        UserInfoActivity.this.ivCamera.setVisibility(0);
                    }
                    UserInfoActivity.this.avatarAnimation = null;
                }

                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationCancel(Animator animation) {
                    UserInfoActivity.this.avatarAnimation = null;
                }
            });
            this.avatarAnimation.start();
            return;
        }
        if (show) {
            this.avatarProgressView.setAlpha(1.0f);
            this.avatarProgressView.setVisibility(0);
            this.ivCamera.setVisibility(8);
        } else {
            this.avatarProgressView.setAlpha(0.0f);
            this.avatarProgressView.setVisibility(4);
            this.ivCamera.setVisibility(0);
        }
    }

    @Override // im.uwrkaxlmjj.ui.components.ImageUpdater.ImageUpdaterDelegate
    public void didUploadPhoto(final TLRPC.InputFile file, final TLRPC.PhotoSize bigSize, final TLRPC.PhotoSize smallSize) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$UserInfoActivity$UL58_coI2IyJ1gndAAYArjKM7eE
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$didUploadPhoto$7$UserInfoActivity(file, smallSize, bigSize);
            }
        });
    }

    public /* synthetic */ void lambda$didUploadPhoto$7$UserInfoActivity(TLRPC.InputFile file, TLRPC.PhotoSize smallSize, TLRPC.PhotoSize bigSize) {
        if (file != null) {
            TLRPC.TL_photos_uploadProfilePhoto req = new TLRPC.TL_photos_uploadProfilePhoto();
            req.file = file;
            ConnectionsManager.getInstance(this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$UserInfoActivity$ozADQl3CqUOivLnFQjBznfbGXNU
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$null$6$UserInfoActivity(tLObject, tL_error);
                }
            });
        } else {
            this.avatar = smallSize.location;
            this.avatarBig = bigSize.location;
            this.avatarImage.setImage(ImageLocation.getForLocal(this.avatar), "50_50", this.avatarDrawable, (Object) null);
            showAvatarProgress(true, false);
        }
    }

    public /* synthetic */ void lambda$null$6$UserInfoActivity(TLObject response, TLRPC.TL_error error) {
        if (error == null) {
            TLRPC.User user = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(UserConfig.getInstance(this.currentAccount).getClientUserId()));
            if (user == null) {
                user = UserConfig.getInstance(this.currentAccount).getCurrentUser();
                if (user != null) {
                    MessagesController.getInstance(this.currentAccount).putUser(user, false);
                } else {
                    return;
                }
            } else {
                UserConfig.getInstance(this.currentAccount).setCurrentUser(user);
            }
            TLRPC.TL_photos_photo photo = (TLRPC.TL_photos_photo) response;
            ArrayList<TLRPC.PhotoSize> sizes = photo.photo.sizes;
            TLRPC.PhotoSize small = FileLoader.getClosestPhotoSizeWithSize(sizes, 150);
            TLRPC.PhotoSize big = FileLoader.getClosestPhotoSizeWithSize(sizes, CodeUtils.DEFAULT_REQ_HEIGHT);
            user.photo = new TLRPC.TL_userProfilePhoto();
            user.photo.photo_id = photo.photo.id;
            if (small != null) {
                user.photo.photo_small = small.location;
            }
            if (big != null) {
                user.photo.photo_big = big.location;
            } else if (small != null) {
                user.photo.photo_small = small.location;
            }
            if (photo != null) {
                if (small != null && this.avatar != null) {
                    File destFile = FileLoader.getPathToAttach(small, true);
                    File src = FileLoader.getPathToAttach(this.avatar, true);
                    src.renameTo(destFile);
                    String oldKey = this.avatar.volume_id + "_" + this.avatar.local_id + "@50_50";
                    String newKey = small.location.volume_id + "_" + small.location.local_id + "@50_50";
                    ImageLoader.getInstance().replaceImageInCache(oldKey, newKey, ImageLocation.getForUser(user, false), true);
                }
                if (big != null && this.avatarBig != null) {
                    File destFile2 = FileLoader.getPathToAttach(big, true);
                    File src2 = FileLoader.getPathToAttach(this.avatarBig, true);
                    src2.renameTo(destFile2);
                }
            }
            MessagesStorage.getInstance(this.currentAccount).clearUserPhotos(user.id);
            ArrayList<TLRPC.User> users = new ArrayList<>();
            users.add(user);
            MessagesStorage.getInstance(this.currentAccount).putUsersAndChats(users, null, false, true);
        }
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$UserInfoActivity$gZp0Oen5JkBGwPOdEjH3aA4oN-Q
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$5$UserInfoActivity();
            }
        });
    }

    public /* synthetic */ void lambda$null$5$UserInfoActivity() {
        this.avatar = null;
        this.avatarBig = null;
        updateUserData();
        showAvatarProgress(false, true);
        NotificationCenter.getInstance(this.currentAccount).postNotificationName(NotificationCenter.updateInterfaces, Integer.valueOf(MessagesController.UPDATE_MASK_ALL));
        NotificationCenter.getInstance(this.currentAccount).postNotificationName(NotificationCenter.mainUserInfoChanged, new Object[0]);
        UserConfig.getInstance(this.currentAccount).saveConfig(true);
    }

    private void getFullUser() {
        if (this.requesting) {
            return;
        }
        this.requesting = true;
        TLRPCContacts.CL_user_getFulluser req = new TLRPCContacts.CL_user_getFulluser();
        req.inputUser = getMessagesController().getInputUser(UserConfig.getInstance(this.currentAccount).getCurrentUser());
        getConnectionsManager().bindRequestToGuid(getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$UserInfoActivity$2vtP1Yta4obTL9083eyPF5PpHK4
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$getFullUser$9$UserInfoActivity(tLObject, tL_error);
            }
        }), this.classGuid);
    }

    public /* synthetic */ void lambda$getFullUser$9$UserInfoActivity(final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$UserInfoActivity$N9p11xC7ECtVceb97IlYvj0Tg1Q
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$8$UserInfoActivity(error, response);
            }
        });
    }

    public /* synthetic */ void lambda$null$8$UserInfoActivity(TLRPC.TL_error error, TLObject response) {
        if (!isFinishing() && error == null && (response instanceof TLRPCContacts.CL_userFull_v1)) {
            TLRPCContacts.CL_userFull_v1 cL_userFull_v1 = (TLRPCContacts.CL_userFull_v1) response;
            this.mUserFull = cL_userFull_v1;
            if (cL_userFull_v1.getExtendBean() != null) {
                initExtraUserInfoData(this.mUserFull.getExtendBean());
                if (this.mUserFull.getExtendBean().needCompletedUserInfor()) {
                    presentFragment(new ChangePersonalInformationActivity(this.currentAccount));
                }
            }
        }
        this.requesting = false;
    }

    private void updateUserExtraInformation() {
        TLRPCLogin.TL_account_updateUserDetail req = new TLRPCLogin.TL_account_updateUserDetail();
        long mills = TimeUtils.string2Millis(this.tvBirthday.getText().toString(), "yyyy-MM-dd");
        req.birthday = (int) (mills / 1000);
        if (req.birthday == 0) {
            return;
        }
        getConnectionsManager().bindRequestToGuid(getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$UserInfoActivity$gZhB0-_DqxLD3R2Dsm1l0Jl6_Dg
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$updateUserExtraInformation$11$UserInfoActivity(tLObject, tL_error);
            }
        }), this.classGuid);
    }

    public /* synthetic */ void lambda$updateUserExtraInformation$11$UserInfoActivity(final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$UserInfoActivity$kX-tla7emwpLd23xtc0ZS1HDhr8
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$10$UserInfoActivity(error, response);
            }
        });
    }

    public /* synthetic */ void lambda$null$10$UserInfoActivity(TLRPC.TL_error error, TLObject response) {
        TLRPCContacts.CL_userFull_v1 cL_userFull_v1;
        TLRPCContacts.CL_userFull_v1 cL_userFull_v12;
        if (error != null) {
            if (this.tvBirthday != null && (cL_userFull_v12 = this.mUserFull) != null && cL_userFull_v12.getExtendBean() != null) {
                this.tvBirthday.setText(TimeUtils.millis2String(((long) this.mUserFull.getExtendBean().birthday) * 1000, "yyyy-MM-dd"));
            }
            if (error.text != null) {
                if (error.text.contains("ALREDY_CHANGE")) {
                    AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
                    builder.setTitle(LocaleController.getString(R.string.AppName));
                    builder.setMessage(LocaleController.getString(R.string.YouHadModifiedOnceCannotModifyAgain));
                    builder.setPositiveButton(LocaleController.getString(R.string.OK), null);
                    showDialog(builder.create());
                    return;
                }
                if (error.code == 400 || error.text.contains("rpcerror")) {
                    ToastUtils.show(R.string.SetupFail);
                    return;
                } else {
                    ToastUtils.show((CharSequence) LocaleController.getString(R.string.OperationFailedPleaseTryAgain));
                    return;
                }
            }
            return;
        }
        if ((response instanceof TLRPC.UserFull) && this.tvBirthday != null && (cL_userFull_v1 = this.mUserFull) != null && cL_userFull_v1.getExtendBean() != null) {
            this.mUserFull.getExtendBean().birthday = (int) (TimeUtils.string2Millis(this.tvBirthday.getText().toString().trim(), "yyyy-MM-dd") / 1000);
        }
    }

    private void showSelectBirthDialog() {
        if (this.mTimePickerBuilder == null) {
            this.mTimePickerBuilder = TimeWheelPickerDialog.getDefaultBuilder(getParentActivity(), new OnTimeSelectListener() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$UserInfoActivity$lGPN5HvQxy-RYoHZ--3W2dADwr8
                @Override // com.bigkoo.pickerview.listener.OnTimeSelectListener
                public final void onTimeSelect(Date date, View view) {
                    this.f$0.lambda$showSelectBirthDialog$12$UserInfoActivity(date, view);
                }
            });
        }
        if (!TextUtils.isEmpty(((Object) this.tvBirthday.getText()) + "")) {
            Calendar calendar = Calendar.getInstance();
            calendar.setTime(TimeUtils.string2Date(this.tvBirthday.getText().toString().trim(), "yyyy-MM-dd"));
            this.mTimePickerBuilder.setDate(calendar);
        } else {
            this.mTimePickerBuilder.setDate(Calendar.getInstance());
        }
        showDialog(this.mTimePickerBuilder.build());
    }

    public /* synthetic */ void lambda$showSelectBirthDialog$12$UserInfoActivity(Date date, View v) {
        String dateStr = TimeUtils.date2String(date, "yyyy-MM-dd");
        this.tvBirthday.setText(dateStr);
        updateUserExtraInformation();
    }
}
