package im.uwrkaxlmjj.ui.hui.contacts;

import android.content.Context;
import android.content.DialogInterface;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.UserObject;
import im.uwrkaxlmjj.messenger.utils.DrawableUtils;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenu;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.hviews.MryEditText;
import im.uwrkaxlmjj.ui.hviews.dialogs.XDialog;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class GreetEditActivity extends BaseFragment {
    public static final int CONTACT_ADD_REPLY = 1;
    public static final int CONTACT_ADD_REQUEST = 0;
    private final int DONE;
    private GreetEditDelegate delegate;
    private Drawable deleteDrawable;
    private MryEditText etGreetEditView;
    private ImageView ivClearGreetView;
    private TextView tvGreetDescView;
    private TextView tvOkView;
    private int type;
    private TLRPC.User user;

    public interface GreetEditDelegate {
        void onFinish(String str);
    }

    public void setDelegate(GreetEditDelegate delegate) {
        this.delegate = delegate;
    }

    public GreetEditActivity(Bundle args) {
        super(args);
        this.DONE = 1;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        super.onFragmentCreate();
        this.user = getUserConfig().getCurrentUser();
        if (this.arguments != null) {
            this.type = this.arguments.getInt("type", 0);
            return true;
        }
        return true;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.fragmentView = LayoutInflater.from(context).inflate(R.layout.activity_greet_edit_layout, (ViewGroup) null, false);
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        initActionBar();
        initView();
        setNote();
        return this.fragmentView;
    }

    private void initActionBar() {
        if (this.type == 0) {
            this.actionBar.setTitle(LocaleController.getString("RequestValidation", R.string.RequestValidation));
        } else {
            this.actionBar.setTitle(LocaleController.getString("Reply", R.string.Reply));
        }
        this.actionBar.setAllowOverlayTitle(true);
        this.actionBar.setCastShadows(true);
        this.actionBar.setActionBarMenuOnItemClick(new AnonymousClass1());
        this.actionBar.setBackButtonImage(R.id.ic_back);
        ActionBarMenu menu = this.actionBar.createMenu();
        this.tvOkView = new TextView(getParentActivity());
        menu.addItem(1, LocaleController.getString("Send", R.string.Send));
        TextView textView = (TextView) menu.getItem(1).getContentView();
        this.tvOkView = textView;
        textView.setTextColor(Theme.getColor(Theme.key_actionBarDefaultTitle));
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.hui.contacts.GreetEditActivity$1, reason: invalid class name */
    class AnonymousClass1 extends ActionBar.ActionBarMenuOnItemClick {
        AnonymousClass1() {
        }

        @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
        public void onItemClick(int id) {
            if (id == -1) {
                GreetEditActivity.this.finishFragment();
                return;
            }
            if (id == 1) {
                if (GreetEditActivity.this.type == 0) {
                    if (GreetEditActivity.this.etGreetEditView.getText().toString().length() >= 100) {
                        ToastUtils.show((CharSequence) LocaleController.getString(R.string.apply_info_too_long));
                        return;
                    }
                    XDialog.Builder builder = new XDialog.Builder(GreetEditActivity.this.getParentActivity());
                    builder.setTitle(LocaleController.getString("AddFriends", R.string.AddFriends));
                    builder.setMessage(LocaleController.getString("SendContactApplyText", R.string.SendContactApplyText));
                    builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
                    builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.contacts.GreetEditActivity.1.1
                        @Override // android.content.DialogInterface.OnClickListener
                        public void onClick(DialogInterface dialog, int which) {
                            if (GreetEditActivity.this.delegate != null) {
                                String greet = GreetEditActivity.this.etGreetEditView.getText().toString().trim();
                                if (TextUtils.isEmpty(greet)) {
                                    greet = GreetEditActivity.this.etGreetEditView.getHint().toString().trim();
                                }
                                GreetEditActivity.this.delegate.onFinish(greet);
                            }
                            GreetEditActivity.this.finishFragment();
                        }
                    });
                    builder.create().show();
                    return;
                }
                XDialog.Builder builder2 = new XDialog.Builder(GreetEditActivity.this.getParentActivity());
                builder2.setTitle("消息回复");
                builder2.setMessage("您确定要回复该条消息吗！");
                builder2.setNegativeButton("取消", null);
                builder2.setPositiveButton("确定", new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$GreetEditActivity$1$-zDU9dS_m4IwSuhzQnYRQhxu6RY
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i) {
                        this.f$0.lambda$onItemClick$0$GreetEditActivity$1(dialogInterface, i);
                    }
                });
                builder2.create().show();
            }
        }

        public /* synthetic */ void lambda$onItemClick$0$GreetEditActivity$1(DialogInterface dialog, int which) {
            GreetEditActivity.this.sendReplyMessage();
            GreetEditActivity.this.finishFragment();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void sendReplyMessage() {
    }

    private void initView() {
        this.fragmentView.findViewById(R.attr.content).setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
        this.etGreetEditView = (MryEditText) this.fragmentView.findViewById(R.attr.etGreetEditView);
        this.ivClearGreetView = (ImageView) this.fragmentView.findViewById(R.attr.ivClearGreetView);
        TextView textView = (TextView) this.fragmentView.findViewById(R.attr.tvGreetDescView);
        this.tvGreetDescView = textView;
        if (this.type == 1) {
            textView.setVisibility(8);
        }
        this.tvGreetDescView.setText(LocaleController.getString("ReqeustText", R.string.ReqeustText));
        if (this.type == 1) {
            this.etGreetEditView.setHint(LocaleController.getString("InputReplyContent", R.string.InputReplyContent));
        } else {
            this.etGreetEditView.setHint(LocaleController.getString("HelloText", R.string.HelloText) + UserObject.getName(this.user));
        }
        this.etGreetEditView.setHintColor(Theme.key_windowBackgroundWhiteHintText);
        Drawable drawable = getParentActivity().getResources().getDrawable(R.drawable.delete);
        this.deleteDrawable = drawable;
        Drawable drawableTintDrawable = DrawableUtils.tintDrawable(drawable, Theme.getColor(Theme.key_windowBackgroundValueText1));
        this.deleteDrawable = drawableTintDrawable;
        drawableTintDrawable.setBounds(0, 0, drawableTintDrawable.getIntrinsicWidth(), this.deleteDrawable.getIntrinsicHeight());
        this.ivClearGreetView.setImageDrawable(this.deleteDrawable);
        this.etGreetEditView.addTextChangedListener(new TextWatcher() { // from class: im.uwrkaxlmjj.ui.hui.contacts.GreetEditActivity.2
            @Override // android.text.TextWatcher
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            @Override // android.text.TextWatcher
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                GreetEditActivity.this.ivClearGreetView.setVisibility(s.length() > 0 ? 0 : 8);
            }

            @Override // android.text.TextWatcher
            public void afterTextChanged(Editable s) {
            }
        });
        this.ivClearGreetView.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$GreetEditActivity$D0vg0daZxsWMgMeQoYOUMgWPgVM
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$initView$0$GreetEditActivity(view);
            }
        });
    }

    public /* synthetic */ void lambda$initView$0$GreetEditActivity(View v) {
        this.etGreetEditView.setText("");
    }

    private void setNote() {
    }

    private void sendMessage() {
    }
}
