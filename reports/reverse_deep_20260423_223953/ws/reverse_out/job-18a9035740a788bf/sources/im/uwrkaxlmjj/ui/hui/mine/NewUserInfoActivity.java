package im.uwrkaxlmjj.ui.hui.mine;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.ServiceConnection;
import android.graphics.Bitmap;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.bigkoo.pickerview.listener.OnOptionsSelectListener;
import com.blankj.utilcode.util.TimeUtils;
import com.king.zxing.util.CodeUtils;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.BuildVars;
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
import im.uwrkaxlmjj.tgnet.ParamsUtil;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.tgnet.TLRPCContacts;
import im.uwrkaxlmjj.tgnet.TLRPCLogin;
import im.uwrkaxlmjj.ui.AddAccountActivity;
import im.uwrkaxlmjj.ui.ChangeNameActivity;
import im.uwrkaxlmjj.ui.ChangeSignActivity;
import im.uwrkaxlmjj.ui.ChangeUsernameActivity;
import im.uwrkaxlmjj.ui.SelectBirthdayActivity;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.components.ImageUpdater;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.RadialProgressView;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.dialogs.BottomDialog;
import im.uwrkaxlmjj.ui.dialogs.OptionsWheelPickerDialog;
import im.uwrkaxlmjj.ui.hcells.MryDividerCell;
import im.uwrkaxlmjj.ui.hcells.TextSettingCell;
import im.uwrkaxlmjj.ui.hui.discovery.ActionIntroActivity;
import im.uwrkaxlmjj.ui.hui.login.LoginPasswordContronllerActivity;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import mpEIGo.juqQQs.esbSDO.R;
import org.slf4j.Marker;

/* JADX INFO: loaded from: classes5.dex */
public class NewUserInfoActivity extends BaseFragment implements ImageUpdater.ImageUpdaterDelegate, NotificationCenter.NotificationCenterDelegate {
    private int addAccountRow;
    private TLRPC.FileLocation avatar;
    private AnimatorSet avatarAnimation;
    private TLRPC.FileLocation avatarBig;
    private int avatarRow;
    private int birthRow;
    private Context context;
    private int genderRow;
    private int gestureCodeRow;
    private ImageUpdater imageUpdater;
    private ListAdapter listAdapter;
    private RecyclerListView listView;
    private int loginPwdRow;
    private int logoutEmptyRow;
    private int logoutRow;
    private OptionsWheelPickerDialog.Builder<String> mGenderPickerBulder;
    ServiceConnection mServerServiceConnection;
    private int nicknameRow;
    private int phoneRow;
    private int qrcodeEmptyRow;
    private int qrcodeRow;
    private int rowCount;
    private int signEmptyRow;
    private int signRow;
    private TLRPCContacts.CL_userFull_v1 userFull;
    private int usernameRow;

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
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.updateInterfaces);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.userFullInfoDidLoad);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.loginPasswordSetSuccess);
        TLRPC.UserFull full = MessagesController.getInstance(this.currentAccount).getUserFull(getUserConfig().getClientUserId());
        if (full instanceof TLRPCContacts.CL_userFull_v1) {
            this.userFull = (TLRPCContacts.CL_userFull_v1) full;
        }
        MessagesController.getInstance(this.currentAccount).loadFullUser(getUserConfig().getCurrentUser(), this.classGuid, true);
        ImageUpdater imageUpdater = new ImageUpdater();
        this.imageUpdater = imageUpdater;
        imageUpdater.parentFragment = this;
        this.imageUpdater.delegate = this;
        return super.onFragmentCreate();
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

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.context = context;
        this.fragmentView = new FrameLayout(context);
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        initActionBar();
        initList(context);
        return this.fragmentView;
    }

    private void initActionBar() {
        this.actionBar.setCastShadows(false);
        this.actionBar.setTitle(LocaleController.getString("InfoEdit", R.string.InfoEdit));
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.hui.mine.NewUserInfoActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    NewUserInfoActivity.this.finishFragment();
                }
            }
        });
    }

    private void initList(final Context context) {
        RecyclerListView recyclerListView = new RecyclerListView(context);
        this.listView = recyclerListView;
        recyclerListView.setLayoutManager(new LinearLayoutManager(context));
        RecyclerListView recyclerListView2 = this.listView;
        ListAdapter listAdapter = new ListAdapter();
        this.listAdapter = listAdapter;
        recyclerListView2.setAdapter(listAdapter);
        this.listView.setLayoutParams(new ViewGroup.LayoutParams(-1, -1));
        ((FrameLayout) this.fragmentView).setBackgroundColor(Theme.getColor(Theme.key_dialogBackground));
        ((FrameLayout) this.fragmentView).addView(this.listView, LayoutHelper.createFrame(-1, -1, AndroidUtilities.dp(10.0f), AndroidUtilities.dp(0.0f), AndroidUtilities.dp(10.0f), AndroidUtilities.dp(0.0f)));
        this.listView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$NewUserInfoActivity$WBhbJUbj3tSKfXuGreIU4XXOKig
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public final void onItemClick(View view, int i) {
                this.f$0.lambda$initList$3$NewUserInfoActivity(context, view, i);
            }
        });
        updateRows();
    }

    public /* synthetic */ void lambda$initList$3$NewUserInfoActivity(Context context, View view, int position) {
        TLRPC.User user = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(UserConfig.getInstance(this.currentAccount).getClientUserId()));
        if (position == this.avatarRow) {
            BottomDialog dialog = new BottomDialog(context);
            dialog.addDialogItem(new BottomDialog.NormalTextItem(0, LocaleController.getString("FromCamera", R.string.FromCamera), true));
            dialog.addDialogItem(new BottomDialog.NormalTextItem(1, LocaleController.getString("FromGallery", R.string.FromGallery), false));
            dialog.setOnItemClickListener(new BottomDialog.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$NewUserInfoActivity$8rGrdgtekHDBJ1dOcKuYiaKQjM4
                @Override // im.uwrkaxlmjj.ui.dialogs.BottomDialog.OnItemClickListener
                public final void onItemClick(int i, View view2) {
                    this.f$0.lambda$null$0$NewUserInfoActivity(i, view2);
                }
            });
            showDialog(dialog);
            return;
        }
        if (position == this.nicknameRow) {
            presentFragment(new ChangeNameActivity());
            return;
        }
        if (position == this.usernameRow) {
            AlertDialog.Builder ub = new AlertDialog.Builder(context);
            ub.setTitle(LocaleController.getString(R.string.AppName));
            ub.setMessage(LocaleController.getString(R.string.ChangeAppNameCodeTips));
            ub.setNegativeButton(LocaleController.getString(R.string.Cancel), null);
            ub.setPositiveButton(LocaleController.getString(R.string.Modify), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$NewUserInfoActivity$mTosDbZthDTy1RhCwkSQP_B-_cw
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    this.f$0.lambda$null$1$NewUserInfoActivity(dialogInterface, i);
                }
            });
            showDialog(ub.create());
            return;
        }
        if (position == this.qrcodeRow) {
            BaseFragment fragment = new QrCodeActivity(user.id);
            presentFragment(fragment);
            return;
        }
        if (position == this.loginPwdRow) {
            presentFragment(new LoginPasswordContronllerActivity(0, null));
            return;
        }
        if (position == this.phoneRow) {
            presentFragment(new ActionIntroActivity(3));
            return;
        }
        if (position == this.birthRow) {
            TLRPCContacts.CL_userFull_v1 cL_userFull_v1 = this.userFull;
            if (cL_userFull_v1 != null) {
                presentFragment(new SelectBirthdayActivity(cL_userFull_v1));
                return;
            }
            return;
        }
        if (position == this.genderRow) {
            TLRPCContacts.CL_userFull_v1 cL_userFull_v12 = this.userFull;
            return;
        }
        if (position == this.signRow) {
            TLRPCContacts.CL_userFull_v1 cL_userFull_v13 = this.userFull;
            if (cL_userFull_v13 != null) {
                presentFragment(new ChangeSignActivity(cL_userFull_v13));
                return;
            }
            return;
        }
        if (position == this.addAccountRow) {
            presentFragment(new AddAccountActivity());
            return;
        }
        if (position == this.logoutRow) {
            if (ApplicationLoader.mbytAVideoCallBusy == 0) {
                AlertDialog.Builder builder = new AlertDialog.Builder(context);
                builder.setMessage(LocaleController.getString("AreYouSureLogout", R.string.AreYouSureLogout));
                builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
                builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$NewUserInfoActivity$TS5OabhdE09nc4gfSXHFYwjJkSc
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i) {
                        this.f$0.lambda$null$2$NewUserInfoActivity(dialogInterface, i);
                    }
                });
                builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
                showDialog(builder.create());
                return;
            }
            ToastUtils.show((CharSequence) LocaleController.getString(R.string.visual_call_stop_login_out));
        }
    }

    public /* synthetic */ void lambda$null$0$NewUserInfoActivity(int id, View v) {
        if (id == 0) {
            this.imageUpdater.openCamera();
        } else if (id == 1) {
            this.imageUpdater.openGallery();
        }
    }

    public /* synthetic */ void lambda$null$1$NewUserInfoActivity(DialogInterface dialog, int which) {
        presentFragment(new ChangeUsernameActivity());
    }

    public /* synthetic */ void lambda$null$2$NewUserInfoActivity(DialogInterface dialogInterface, int i) {
        MessagesController.getInstance(this.currentAccount).performLogout(1);
    }

    private void updateRows() {
        this.rowCount = 0;
        int i = 0 + 1;
        this.rowCount = i;
        this.avatarRow = 0;
        int i2 = i + 1;
        this.rowCount = i2;
        this.nicknameRow = i;
        this.usernameRow = -1;
        int i3 = i2 + 1;
        this.rowCount = i3;
        this.usernameRow = i2;
        int i4 = i3 + 1;
        this.rowCount = i4;
        this.qrcodeEmptyRow = i3;
        this.rowCount = i4 + 1;
        this.loginPwdRow = i4;
        if (!BuildVars.RELEASE_VERSION) {
            int i5 = this.rowCount;
            this.rowCount = i5 + 1;
            this.gestureCodeRow = i5;
        }
        int i6 = this.rowCount;
        int i7 = i6 + 1;
        this.rowCount = i7;
        this.birthRow = i6;
        int i8 = i7 + 1;
        this.rowCount = i8;
        this.genderRow = i7;
        int i9 = i8 + 1;
        this.rowCount = i9;
        this.signEmptyRow = i8;
        int i10 = i9 + 1;
        this.rowCount = i10;
        this.addAccountRow = i9;
        int i11 = i10 + 1;
        this.rowCount = i11;
        this.logoutEmptyRow = i10;
        this.rowCount = i11 + 1;
        this.logoutRow = i11;
        ListAdapter listAdapter = this.listAdapter;
        if (listAdapter != null) {
            listAdapter.notifyDataSetChanged();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void saveImage(final BackupImageView avatarImage) {
        new Thread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$NewUserInfoActivity$bpFvOu_Pds3mWFQEYq5S6Dwvhn8
            @Override // java.lang.Runnable
            public final void run() {
                NewUserInfoActivity.lambda$saveImage$4(avatarImage);
            }
        }).start();
    }

    static /* synthetic */ void lambda$saveImage$4(BackupImageView avatarImage) {
        while (avatarImage.getImageReceiver().getBitmap() == null) {
            try {
                Thread.sleep(10L);
            } catch (Exception e) {
                e.printStackTrace();
                return;
            }
        }
        Bitmap bitmap = avatarImage.getImageReceiver().getBitmap();
        File file = new File(AndroidUtilities.getCacheDir().getPath() + File.separator + "user_avatar.jpg");
        if (file.exists()) {
            file.delete();
        }
        FileOutputStream out = new FileOutputStream(file);
        bitmap.compress(Bitmap.CompressFormat.JPEG, 100, out);
        out.flush();
        out.close();
    }

    private void showAvatarProgress(final boolean show, boolean animated) {
        RecyclerView.ViewHolder holder = this.listView.findViewHolderForAdapterPosition(this.avatarRow);
        if (holder == null) {
            return;
        }
        final RadialProgressView avatarProgressView = (RadialProgressView) holder.itemView.findViewById(R.attr.rpvAvatar);
        AnimatorSet animatorSet = this.avatarAnimation;
        if (animatorSet != null) {
            animatorSet.cancel();
            this.avatarAnimation = null;
        }
        if (animated) {
            this.avatarAnimation = new AnimatorSet();
            if (show) {
                avatarProgressView.setVisibility(0);
            }
            this.avatarAnimation.setDuration(180L);
            this.avatarAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.hui.mine.NewUserInfoActivity.2
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animation) {
                    if (NewUserInfoActivity.this.avatarAnimation == null) {
                        return;
                    }
                    if (!show) {
                        avatarProgressView.setVisibility(4);
                    }
                    NewUserInfoActivity.this.avatarAnimation = null;
                }

                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationCancel(Animator animation) {
                    NewUserInfoActivity.this.avatarAnimation = null;
                }
            });
            this.avatarAnimation.start();
            return;
        }
        if (show) {
            avatarProgressView.setAlpha(1.0f);
            avatarProgressView.setVisibility(0);
        } else {
            avatarProgressView.setAlpha(0.0f);
            avatarProgressView.setVisibility(4);
        }
    }

    private void showSelectGenderDialog() {
        TLRPCContacts.CL_userFull_v1 cL_userFull_v1 = this.userFull;
        if (cL_userFull_v1 == null || cL_userFull_v1.getExtendBean() == null) {
            return;
        }
        if (this.mGenderPickerBulder == null) {
            List<String> data = new ArrayList<>(Arrays.asList(LocaleController.getString(R.string.PassportFemale), LocaleController.getString(R.string.PassportMale)));
            OptionsWheelPickerDialog.Builder<String> defaultBuilder = OptionsWheelPickerDialog.getDefaultBuilder(getParentActivity(), new OnOptionsSelectListener() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$NewUserInfoActivity$q5cC-dw9f86iNanRfuwO6paSkOg
                @Override // com.bigkoo.pickerview.listener.OnOptionsSelectListener
                public final void onOptionsSelect(int i, int i2, int i3, View view) {
                    this.f$0.lambda$showSelectGenderDialog$5$NewUserInfoActivity(i, i2, i3, view);
                }
            });
            this.mGenderPickerBulder = defaultBuilder;
            defaultBuilder.setPicker(data);
        }
        if (this.userFull.getExtendBean().sex == 1) {
            this.mGenderPickerBulder.setSelectOptions(1);
        } else {
            this.mGenderPickerBulder.setSelectOptions(0);
        }
        showDialog(this.mGenderPickerBulder.build());
    }

    public /* synthetic */ void lambda$showSelectGenderDialog$5$NewUserInfoActivity(int options1, int options2, int options3, View v) {
        int sex = options1 == 0 ? 2 : 1;
        updateUserSex(sex);
    }

    private void updateUserSex(final int sex) {
        TLRPCContacts.CL_userFull_v1 cL_userFull_v1 = this.userFull;
        if (cL_userFull_v1 == null || cL_userFull_v1.getExtendBean() == null) {
            return;
        }
        TLRPCLogin.TL_account_updateUserDetail req = new TLRPCLogin.TL_account_updateUserDetail();
        req.birthday = 0;
        req.extend = new TLRPC.TL_dataJSON();
        req.extend.data = ParamsUtil.toJsonObj(new String[]{"Sex"}, Integer.valueOf(sex)).toJSONString();
        getConnectionsManager().bindRequestToGuid(getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$NewUserInfoActivity$YTVHAS9WQ7cgXluHLXqic9Y47hU
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$updateUserSex$7$NewUserInfoActivity(sex, tLObject, tL_error);
            }
        }), this.classGuid);
    }

    public /* synthetic */ void lambda$updateUserSex$7$NewUserInfoActivity(final int sex, final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$NewUserInfoActivity$0Ru9qWEprwrDxUvm8Xl02KtPzic
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$6$NewUserInfoActivity(error, response, sex);
            }
        });
    }

    public /* synthetic */ void lambda$null$6$NewUserInfoActivity(TLRPC.TL_error error, TLObject response, int sex) {
        if (error != null) {
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
        if (response instanceof TLRPC.UserFull) {
            TLRPCContacts.CL_userFull_v1 cL_userFull_v1 = this.userFull;
            if (cL_userFull_v1 != null && cL_userFull_v1.getExtendBean() != null) {
                this.userFull.getExtendBean().sex = sex;
                getMessagesController().loadFullUser(this.userFull.user, this.classGuid, true);
            }
            ListAdapter listAdapter = this.listAdapter;
            if (listAdapter != null) {
                listAdapter.notifyItemChanged(this.genderRow);
            }
        }
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        if (id == NotificationCenter.updateInterfaces) {
            updateRows();
            return;
        }
        if (id == NotificationCenter.userFullInfoDidLoad) {
            int userId = ((Integer) args[0]).intValue();
            if (userId == getUserConfig().getClientUserId()) {
                this.userFull = (TLRPCContacts.CL_userFull_v1) args[1];
                updateRows();
                return;
            }
            return;
        }
        int userId2 = NotificationCenter.loginPasswordSetSuccess;
        if (id == userId2) {
            MessagesController.getInstance(this.currentAccount).loadFullUser(this.userFull.user, this.classGuid, true);
        }
    }

    @Override // im.uwrkaxlmjj.ui.components.ImageUpdater.ImageUpdaterDelegate
    public void didUploadPhoto(final TLRPC.InputFile file, final TLRPC.PhotoSize bigSize, final TLRPC.PhotoSize smallSize) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$NewUserInfoActivity$VODiiUBpBdIyHBxJxMCaRqPwneM
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$didUploadPhoto$10$NewUserInfoActivity(file, smallSize, bigSize);
            }
        });
    }

    public /* synthetic */ void lambda$didUploadPhoto$10$NewUserInfoActivity(TLRPC.InputFile file, TLRPC.PhotoSize smallSize, TLRPC.PhotoSize bigSize) {
        if (file != null) {
            TLRPC.TL_photos_uploadProfilePhoto req = new TLRPC.TL_photos_uploadProfilePhoto();
            req.file = file;
            ConnectionsManager.getInstance(this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$NewUserInfoActivity$K8NxWJLlM6B9p_2efj-8eeqpEB4
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$null$9$NewUserInfoActivity(tLObject, tL_error);
                }
            });
        } else {
            this.avatar = smallSize.location;
            this.avatarBig = bigSize.location;
            showAvatarProgress(true, false);
            updateRows();
        }
    }

    public /* synthetic */ void lambda$null$9$NewUserInfoActivity(TLObject response, TLRPC.TL_error error) {
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
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$NewUserInfoActivity$W8vATflwbFnS7EF8Hk--jm3hIyY
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$8$NewUserInfoActivity();
            }
        });
    }

    public /* synthetic */ void lambda$null$8$NewUserInfoActivity() {
        this.avatar = null;
        this.avatarBig = null;
        showAvatarProgress(false, true);
        NotificationCenter.getInstance(this.currentAccount).postNotificationName(NotificationCenter.updateInterfaces, Integer.valueOf(MessagesController.UPDATE_MASK_ALL));
        NotificationCenter.getInstance(this.currentAccount).postNotificationName(NotificationCenter.mainUserInfoChanged, new Object[0]);
        UserConfig.getInstance(this.currentAccount).saveConfig(true);
        updateRows();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        BackupImageView avatarImage;
        super.onFragmentDestroy();
        RecyclerView.ViewHolder holder = this.listView.findViewHolderForAdapterPosition(this.avatarRow);
        if (holder != null && (avatarImage = (BackupImageView) holder.itemView.findViewById(R.attr.iv_avatar)) != null) {
            avatarImage.setImageDrawable(null);
        }
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.updateInterfaces);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.userFullInfoDidLoad);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.loginPasswordSetSuccess);
        this.mGenderPickerBulder = null;
        this.imageUpdater.clear();
        this.userFull = null;
    }

    private class ListAdapter extends RecyclerListView.SelectionAdapter {
        private boolean mblnUpdateFromInit;

        private ListAdapter() {
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            return holder.getItemViewType() != 3;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view;
            if (viewType == 0) {
                View view2 = new TextSettingCell(NewUserInfoActivity.this.context);
                view2.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                view = view2;
            } else if (viewType == 1) {
                View view3 = LayoutInflater.from(NewUserInfoActivity.this.context).inflate(R.layout.item_user_info_avatar, parent, false);
                view3.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                view = view3;
            } else if (viewType == 2) {
                view = LayoutInflater.from(NewUserInfoActivity.this.context).inflate(R.layout.item_login_add, parent, false);
            } else {
                view = new View(NewUserInfoActivity.this.context);
            }
            return new RecyclerListView.Holder(view);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            String string;
            String loginPwdText;
            int i;
            String str;
            TLRPC.User user = MessagesController.getInstance(NewUserInfoActivity.this.currentAccount).getUser(Integer.valueOf(UserConfig.getInstance(NewUserInfoActivity.this.currentAccount).getClientUserId()));
            int itemViewType = holder.getItemViewType();
            if (itemViewType != 0) {
                if (itemViewType != 1) {
                    if (itemViewType == 2) {
                        LinearLayout parent = (LinearLayout) holder.itemView;
                        MryTextView textView = (MryTextView) parent.findViewById(R.attr.tv_title);
                        if (position != NewUserInfoActivity.this.addAccountRow) {
                            if (position == NewUserInfoActivity.this.logoutRow) {
                                textView.setText(LocaleController.getString(R.string.Signout));
                            }
                        } else {
                            textView.setText(LocaleController.getString(R.string.AddAccount2));
                        }
                        textView.setTextColor(Theme.getColor(Theme.key_contacts_userCellDeleteText));
                        textView.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(8.0f), Theme.getColor(Theme.key_windowBackgroundWhiteBlueButton)));
                        return;
                    }
                    return;
                }
                BackupImageView ivAvatar = (BackupImageView) holder.itemView.findViewById(R.attr.iv_avatar);
                MryTextView tvTitle = (MryTextView) holder.itemView.findViewById(R.attr.tv_title);
                MryDividerCell divider = (MryDividerCell) holder.itemView.findViewById(R.attr.divider);
                if (position != NewUserInfoActivity.this.avatarRow) {
                    if (position == NewUserInfoActivity.this.qrcodeRow) {
                        tvTitle.setText(LocaleController.getString(R.string.MyQRCode));
                        RelativeLayout.LayoutParams lp = (RelativeLayout.LayoutParams) ivAvatar.getLayoutParams();
                        lp.height = AndroidUtilities.dp(16.0f);
                        lp.width = AndroidUtilities.dp(16.0f);
                        ivAvatar.setLayoutParams(lp);
                        ivAvatar.setImageResource(R.id.ic_my_qrcode);
                        divider.setVisibility(8);
                        return;
                    }
                    return;
                }
                if (user != null) {
                    tvTitle.setText(LocaleController.getString(R.string.PrivacyProfilePhoto));
                    ivAvatar.setRoundRadius(AndroidUtilities.dp(7.5f));
                    Drawable drawableDef = NewUserInfoActivity.this.getParentActivity().getResources().getDrawable(R.drawable.ic_head_def);
                    ivAvatar.setImage(ImageLocation.getForUser(user, false), "50_50", drawableDef, user);
                    if ((user.photo instanceof TLRPC.TL_userProfilePhoto) && !this.mblnUpdateFromInit) {
                        NewUserInfoActivity.this.saveImage(ivAvatar);
                    }
                    this.mblnUpdateFromInit = false;
                }
                holder.itemView.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), 0.0f, 0.0f, Theme.getColor(Theme.key_windowBackgroundWhite)));
                return;
            }
            TextSettingCell settingCell = (TextSettingCell) holder.itemView;
            string = "";
            if (position != NewUserInfoActivity.this.nicknameRow) {
                if (position != NewUserInfoActivity.this.usernameRow) {
                    if (position != NewUserInfoActivity.this.phoneRow) {
                        if (position != NewUserInfoActivity.this.birthRow) {
                            if (position != NewUserInfoActivity.this.genderRow) {
                                if (position == NewUserInfoActivity.this.signRow) {
                                    settingCell.setTextAndValue(LocaleController.getString(R.string.BioDesc), NewUserInfoActivity.this.userFull != null ? NewUserInfoActivity.this.userFull.about : "", false, true);
                                    settingCell.setBackground(Theme.createRoundRectDrawable(0.0f, 0.0f, AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
                                    return;
                                }
                                if (position == NewUserInfoActivity.this.loginPwdRow || position == NewUserInfoActivity.this.gestureCodeRow) {
                                    if (position == NewUserInfoActivity.this.loginPwdRow) {
                                        loginPwdText = LocaleController.getString(R.string.ModifyLoginPwd);
                                    } else {
                                        loginPwdText = LocaleController.getString(R.string.GestureCodeSet);
                                    }
                                    if (user instanceof TLRPC.TL_user) {
                                        if (position != NewUserInfoActivity.this.loginPwdRow || !((TLRPC.TL_user) user).hasSetLoginPwd) {
                                            if (position == NewUserInfoActivity.this.gestureCodeRow && ((TLRPC.TL_user) user).hasSetGesturePwd) {
                                                loginPwdText = LocaleController.getString(R.string.GestureCodeModify);
                                            }
                                        } else {
                                            loginPwdText = LocaleController.getString(R.string.ModifyLoginPwd);
                                        }
                                    }
                                    settingCell.setText(loginPwdText, false, true);
                                    return;
                                }
                                if (position == NewUserInfoActivity.this.qrcodeRow) {
                                    settingCell.setText(LocaleController.getString(R.string.MyQRCode), false, true);
                                    return;
                                }
                                return;
                            }
                            String string2 = LocaleController.getString(R.string.PassportGender);
                            if (NewUserInfoActivity.this.userFull != null && NewUserInfoActivity.this.userFull.getExtendBean() != null) {
                                if (NewUserInfoActivity.this.userFull.getExtendBean().sex == 1) {
                                    i = R.string.PassportMale;
                                    str = "Male";
                                } else if (NewUserInfoActivity.this.userFull.getExtendBean().sex == 2) {
                                    i = R.string.PassportFemale;
                                    str = "Female";
                                }
                                string = LocaleController.getString(str, i);
                            }
                            settingCell.setTextAndValue(string2, string, false, false);
                            return;
                        }
                        String string3 = LocaleController.getString(R.string.Birthday);
                        if (NewUserInfoActivity.this.userFull != null && NewUserInfoActivity.this.userFull.getExtendBean() != null) {
                            string = TimeUtils.millis2String(((long) NewUserInfoActivity.this.userFull.getExtendBean().birthday) * 1000, LocaleController.getString("yyyy.mm.dd", R.string.formatterYear2));
                        }
                        settingCell.setTextAndValue(string3, string, false, true);
                        return;
                    }
                    String string4 = LocaleController.getString(R.string.PhoneNumber);
                    if (user != null) {
                        string = PhoneFormat.getInstance().format(Marker.ANY_NON_NULL_MARKER + user.phone);
                    }
                    settingCell.setTextAndValue(string4, string, false, true);
                    return;
                }
                settingCell.setTextAndValue(LocaleController.getString(R.string.AppNameCode2), user != null ? user.username.length() > 32 ? user.username.substring(0, 10) : user.username : "", true, true);
                return;
            }
            settingCell.setTextAndValue(LocaleController.getString(R.string.Nickname2), user != null ? user.first_name : "", false, true);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int position) {
            if (position != NewUserInfoActivity.this.avatarRow) {
                if (position != NewUserInfoActivity.this.addAccountRow && position != NewUserInfoActivity.this.logoutRow) {
                    if (position == NewUserInfoActivity.this.qrcodeEmptyRow || position == NewUserInfoActivity.this.signEmptyRow || position == NewUserInfoActivity.this.logoutEmptyRow) {
                        return 3;
                    }
                    return 0;
                }
                return 2;
            }
            return 1;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            return NewUserInfoActivity.this.rowCount;
        }
    }
}
