package im.uwrkaxlmjj.ui.hui.contacts;

import android.content.Context;
import android.content.DialogInterface;
import android.os.Bundle;
import android.text.Editable;
import android.text.InputFilter;
import android.text.Spanned;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.view.LayoutInflater;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.TextView;
import butterknife.BindView;
import butterknife.OnClick;
import com.blankj.utilcode.util.KeyboardUtils;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.tgnet.TLRPCContacts;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenu;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.dialogs.WalletDialog;
import im.uwrkaxlmjj.ui.hui.contacts.SelectGroupingActivity;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class NoteAndGroupingEditActivity extends BaseFragment {
    public static final int ADD_CONTACTS = 1;
    public static final int CONTACTS_PROFILE = 2;
    private final int DONE;
    private int defaultGroupId;
    private String defaultGroupName;
    private AddInfoDelegate delegate;

    @BindView(R.attr.etNoteEditView)
    EditText etNoteEditView;

    @BindView(R.attr.flNoteSettingLayout)
    FrameLayout flNoteSettingLayout;

    @BindView(R.attr.ivClearNoteView)
    ImageView ivClearNoteView;
    private TLRPCContacts.TL_contactsGroupInfo selectedGroup;

    @BindView(R.attr.tvGroupDescView)
    TextView tvGroupDescView;

    @BindView(R.attr.tvGroupingSettingView)
    TextView tvGroupingSettingView;

    @BindView(R.attr.tvNoteDescView)
    TextView tvNoteDescView;
    private int type;
    private TLRPC.User user;
    private String userNote;
    private int user_id;

    public interface AddInfoDelegate {
        void onFinish(int i, String str, String str2);
    }

    public void setDelegate(AddInfoDelegate delegate) {
        this.delegate = delegate;
    }

    public NoteAndGroupingEditActivity(Bundle args) {
        super(args);
        this.DONE = 1;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        this.swipeBackEnabled = false;
        if (this.arguments != null) {
            this.user_id = this.arguments.getInt("user_id");
            this.type = this.arguments.getInt("type", 0);
            this.defaultGroupId = this.arguments.getInt("groupId");
            this.defaultGroupName = this.arguments.getString("groupName", "");
            this.userNote = this.arguments.getString("userNote", "");
        }
        TLRPC.User user = getMessagesController().getUser(Integer.valueOf(this.user_id));
        this.user = user;
        if (user == null) {
            return false;
        }
        return true;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.fragmentView = LayoutInflater.from(context).inflate(R.layout.activity_note_and_grouping_edit_layout, (ViewGroup) null, false);
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        this.fragmentView.setOnTouchListener(new View.OnTouchListener() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$NoteAndGroupingEditActivity$sQfX9-IeWn7t4bzlgNzCdI3GyUw
            @Override // android.view.View.OnTouchListener
            public final boolean onTouch(View view, MotionEvent motionEvent) {
                return NoteAndGroupingEditActivity.lambda$createView$0(view, motionEvent);
            }
        });
        useButterKnife();
        initActionBar();
        initView();
        return this.fragmentView;
    }

    static /* synthetic */ boolean lambda$createView$0(View v, MotionEvent event) {
        return true;
    }

    private void initActionBar() {
        this.actionBar.setCastShadows(false);
        this.actionBar.setTitle(LocaleController.getString("SetGroupingAndRemarks", R.string.SetGroupingAndRemarks));
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.hui.contacts.NoteAndGroupingEditActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    if (!NoteAndGroupingEditActivity.this.etNoteEditView.getText().toString().equals(NoteAndGroupingEditActivity.this.userNote)) {
                        NoteAndGroupingEditActivity.this.showSaveDialog();
                        return;
                    } else {
                        NoteAndGroupingEditActivity.this.finishFragment();
                        return;
                    }
                }
                if (id == 1) {
                    if (!NoteAndGroupingEditActivity.this.etNoteEditView.getText().toString().equals(NoteAndGroupingEditActivity.this.userNote)) {
                        NoteAndGroupingEditActivity.this.setGroupingAndNote();
                    } else {
                        NoteAndGroupingEditActivity.this.finishFragment();
                    }
                }
            }
        });
        ActionBarMenu menu = this.actionBar.createMenu();
        menu.addItem(1, LocaleController.getString("Done", R.string.Done));
    }

    private void initView() {
        this.tvGroupingSettingView.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
        this.tvGroupingSettingView.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
        this.flNoteSettingLayout.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
        this.tvNoteDescView.setText(LocaleController.getString("NoteSetting", R.string.NoteSetting));
        this.etNoteEditView.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
        this.etNoteEditView.setHint(LocaleController.getString("InputNoteText", R.string.InputNoteText));
        this.etNoteEditView.setHintTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteHintText));
        this.etNoteEditView.setFilters(new InputFilter[]{getLengthFilter(32)});
        this.etNoteEditView.addTextChangedListener(new TextWatcher() { // from class: im.uwrkaxlmjj.ui.hui.contacts.NoteAndGroupingEditActivity.2
            @Override // android.text.TextWatcher
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            @Override // android.text.TextWatcher
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                NoteAndGroupingEditActivity.this.ivClearNoteView.setVisibility(!TextUtils.isEmpty(s) ? 0 : 8);
            }

            @Override // android.text.TextWatcher
            public void afterTextChanged(Editable s) {
            }
        });
        this.tvGroupingSettingView.setText(this.defaultGroupName);
        int i = this.type;
        if (i == 1) {
            this.etNoteEditView.setText(this.userNote);
        } else if (i == 2) {
            EditText editText = this.etNoteEditView;
            String str = this.user.first_name;
            this.userNote = str;
            editText.setText(str);
        }
        this.tvGroupDescView.setVisibility(0);
        this.tvGroupingSettingView.setVisibility(0);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        super.onResume();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showSaveDialog() {
        WalletDialog dialog = new WalletDialog(getParentActivity());
        dialog.setMessage(LocaleController.getString("SaveGroupingChangeTips", R.string.SaveGroupingChangeTips));
        dialog.setPositiveButton(LocaleController.getString("Save", R.string.Save), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$NoteAndGroupingEditActivity$i6ACGF3ivIpF1R-lPSQQJS0ztEo
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                this.f$0.lambda$showSaveDialog$1$NoteAndGroupingEditActivity(dialogInterface, i);
            }
        });
        dialog.setNegativeButton(LocaleController.getString("NotSave", R.string.NotSave), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$NoteAndGroupingEditActivity$7QyRv4D504x6qPzOC7FzxwVE9bg
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                this.f$0.lambda$showSaveDialog$2$NoteAndGroupingEditActivity(dialogInterface, i);
            }
        });
        showDialog(dialog);
    }

    public /* synthetic */ void lambda$showSaveDialog$1$NoteAndGroupingEditActivity(DialogInterface dialogInterface, int i) {
        setGroupingAndNote();
    }

    public /* synthetic */ void lambda$showSaveDialog$2$NoteAndGroupingEditActivity(DialogInterface dialogInterface, int i) {
        finishFragment();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void setGroupingAndNote() {
        if (this.user != null) {
            final AlertDialog alertDialog = new AlertDialog(getParentActivity(), 3);
            TLRPCContacts.TL_setUserGroup req = new TLRPCContacts.TL_setUserGroup();
            TLRPCContacts.TL_contactsGroupInfo tL_contactsGroupInfo = this.selectedGroup;
            req.group_id = tL_contactsGroupInfo != null ? tL_contactsGroupInfo.group_id : Math.max(this.defaultGroupId, 0);
            TLRPCContacts.TL_inputPeerUserChange inputPeer = new TLRPCContacts.TL_inputPeerUserChange();
            inputPeer.access_hash = this.user.access_hash;
            inputPeer.user_id = this.user.id;
            inputPeer.fist_name = this.etNoteEditView.getText().toString();
            req.users.add(inputPeer);
            final int reqId = getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$NoteAndGroupingEditActivity$wXtrEC6MeEl0GbnW_QQBZTxoKNw
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$setGroupingAndNote$4$NoteAndGroupingEditActivity(alertDialog, tLObject, tL_error);
                }
            });
            getConnectionsManager().bindRequestToGuid(reqId, this.classGuid);
            alertDialog.setOnDismissListener(new DialogInterface.OnDismissListener() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$NoteAndGroupingEditActivity$jmPUKx9rw_3pCrVg_bJk_JxgIP0
                @Override // android.content.DialogInterface.OnDismissListener
                public final void onDismiss(DialogInterface dialogInterface) {
                    this.f$0.lambda$setGroupingAndNote$5$NoteAndGroupingEditActivity(reqId, dialogInterface);
                }
            });
            showDialog(alertDialog);
        }
    }

    public /* synthetic */ void lambda$setGroupingAndNote$4$NoteAndGroupingEditActivity(final AlertDialog alertDialog, final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$NoteAndGroupingEditActivity$wc6lAbc5zav-rbXj7NXiDUNLx5k
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$3$NoteAndGroupingEditActivity(alertDialog, error, response);
            }
        });
    }

    public /* synthetic */ void lambda$null$3$NoteAndGroupingEditActivity(AlertDialog alertDialog, TLRPC.TL_error error, TLObject response) {
        alertDialog.dismiss();
        if (error == null) {
            if (response instanceof TLRPC.TL_boolTrue) {
                AddInfoDelegate addInfoDelegate = this.delegate;
                if (addInfoDelegate != null) {
                    TLRPCContacts.TL_contactsGroupInfo tL_contactsGroupInfo = this.selectedGroup;
                    int iMax = tL_contactsGroupInfo != null ? tL_contactsGroupInfo.group_id : Math.max(this.defaultGroupId, 0);
                    TLRPCContacts.TL_contactsGroupInfo tL_contactsGroupInfo2 = this.selectedGroup;
                    addInfoDelegate.onFinish(iMax, tL_contactsGroupInfo2 != null ? tL_contactsGroupInfo2.title : "", this.etNoteEditView.getText().toString());
                }
                finishFragment();
                return;
            }
            ToastUtils.show((CharSequence) "设置失败，请稍后重试");
            return;
        }
        ToastUtils.show((CharSequence) error.text);
    }

    public /* synthetic */ void lambda$setGroupingAndNote$5$NoteAndGroupingEditActivity(int reqId, DialogInterface dialog1) {
        getConnectionsManager().cancelRequest(reqId, true);
    }

    @OnClick({R.attr.tvGroupingSettingView, R.attr.ivClearNoteView})
    public void onViewClicked(View view) {
        int id = view.getId();
        if (id == R.attr.ivClearNoteView) {
            this.etNoteEditView.setText("");
            return;
        }
        if (id == R.attr.tvGroupingSettingView) {
            Bundle bundle = new Bundle();
            bundle.putInt("user_id", this.user_id);
            TLRPCContacts.TL_contactsGroupInfo tL_contactsGroupInfo = this.selectedGroup;
            bundle.putInt("groupId", tL_contactsGroupInfo != null ? tL_contactsGroupInfo.group_id : this.defaultGroupId);
            SelectGroupingActivity selectGroupingActivity = new SelectGroupingActivity(bundle);
            selectGroupingActivity.setDelegate(new SelectGroupingActivity.SelectGroupingActivityDelegate() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$NoteAndGroupingEditActivity$gJCAZ_lmNvwcwxdU-xeYQGoP-CI
                @Override // im.uwrkaxlmjj.ui.hui.contacts.SelectGroupingActivity.SelectGroupingActivityDelegate
                public final void onFinish(TLRPCContacts.TL_contactsGroupInfo tL_contactsGroupInfo2) {
                    this.f$0.lambda$onViewClicked$6$NoteAndGroupingEditActivity(tL_contactsGroupInfo2);
                }
            });
            presentFragment(selectGroupingActivity);
        }
    }

    public /* synthetic */ void lambda$onViewClicked$6$NoteAndGroupingEditActivity(TLRPCContacts.TL_contactsGroupInfo group) {
        this.selectedGroup = group;
        if (group != null) {
            this.tvGroupingSettingView.setText(group.title);
            AddInfoDelegate addInfoDelegate = this.delegate;
            if (addInfoDelegate != null) {
                addInfoDelegate.onFinish(this.selectedGroup.group_id, this.selectedGroup.title, this.user.first_name);
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onPause() {
        super.onPause();
        KeyboardUtils.hideSoftInput(this.etNoteEditView);
    }

    private InputFilter getLengthFilter(final int maxLen) {
        InputFilter filter = new InputFilter() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$NoteAndGroupingEditActivity$eH4A8qMWIrX2yFcfCfPvaB5b7ew
            @Override // android.text.InputFilter
            public final CharSequence filter(CharSequence charSequence, int i, int i2, Spanned spanned, int i3, int i4) {
                return NoteAndGroupingEditActivity.lambda$getLengthFilter$7(maxLen, charSequence, i, i2, spanned, i3, i4);
            }
        };
        return filter;
    }

    static /* synthetic */ CharSequence lambda$getLengthFilter$7(int maxLen, CharSequence src, int start, int end, Spanned dest, int dstart, int dend) {
        int dindex = 0;
        int count = 0;
        while (count <= maxLen && dindex < dest.length()) {
            int dindex2 = dindex + 1;
            char c = dest.charAt(dindex);
            if (c < 128) {
                count++;
            } else {
                count += 2;
            }
            dindex = dindex2;
        }
        if (count > maxLen) {
            return dest.subSequence(0, dindex - 1);
        }
        int sindex = 0;
        while (count <= maxLen && sindex < src.length()) {
            int sindex2 = sindex + 1;
            char c2 = src.charAt(sindex);
            if (c2 < 128) {
                count++;
            } else {
                count += 2;
            }
            sindex = sindex2;
        }
        if (count > maxLen) {
            sindex--;
        }
        return src.subSequence(0, sindex);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onBackPressed() {
        if (!this.etNoteEditView.getText().toString().equals(this.userNote)) {
            showSaveDialog();
            return false;
        }
        return super.onBackPressed();
    }
}
