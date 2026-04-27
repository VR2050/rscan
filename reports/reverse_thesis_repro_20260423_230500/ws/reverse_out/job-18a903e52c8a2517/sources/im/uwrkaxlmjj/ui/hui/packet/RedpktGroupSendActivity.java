package im.uwrkaxlmjj.ui.hui.packet;

import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.text.Editable;
import android.text.InputFilter;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.util.Base64;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.BaseAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.GridView;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ListAdapter;
import android.widget.TextView;
import com.blankj.utilcode.util.SpanUtils;
import com.google.gson.Gson;
import com.litesuits.orm.db.assit.SQLBuilder;
import com.snail.antifake.deviceid.ShellAdbUtils;
import im.uwrkaxlmjj.javaBean.hongbao.UnifyBean;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.BuildVars;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.MessagesStorage;
import im.uwrkaxlmjj.messenger.utils.DataTools;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.SerializedData;
import im.uwrkaxlmjj.tgnet.TLApiModel;
import im.uwrkaxlmjj.tgnet.TLJsonResolve;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.tgnet.TLRPCRedpacket;
import im.uwrkaxlmjj.tgnet.TLRPCWallet;
import im.uwrkaxlmjj.ui.ChatActivity;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.BottomSheet;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.actionbar.XAlertDialog;
import im.uwrkaxlmjj.ui.components.AvatarDrawable;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.dialogs.WalletDialog;
import im.uwrkaxlmjj.ui.hui.adapter.EditInputFilter;
import im.uwrkaxlmjj.ui.hui.adapter.InputNumberFilter;
import im.uwrkaxlmjj.ui.hui.mine.AboutAppActivity;
import im.uwrkaxlmjj.ui.hui.packet.SelecteContactsActivity;
import im.uwrkaxlmjj.ui.hui.packet.bean.RepacketRequest;
import im.uwrkaxlmjj.ui.hui.wallet_public.bean.WalletAccountInfo;
import im.uwrkaxlmjj.ui.hui.wallet_public.bean.WalletConfigBean;
import im.uwrkaxlmjj.ui.hui.wallet_public.utils.WalletDialogUtil;
import im.uwrkaxlmjj.ui.hui.wallet_public.utils.WalletErrorUtil;
import im.uwrkaxlmjj.ui.hviews.SegmenteView;
import im.uwrkaxlmjj.ui.utils.AesUtils;
import im.uwrkaxlmjj.ui.utils.number.StringUtils;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class RedpktGroupSendActivity extends BaseFragment {
    public static final int RPT_GROUP_EXCLUSIVE = 1002;
    public static final int RPT_GROUP_NORMAL = 1000;
    public static final int RPT_GROUP_RANDOM = 1001;
    private WalletAccountInfo accountInfo;
    private BackupImageView bivUserSelected;
    private Button btnRptSend;
    private TLRPC.ChatFull chatFull;
    private EditText etRptAmountEditView;
    private EditText etRptGreetEditView;
    private EditText etRptTargetEditView;
    private ImageView ivCoinLogo;
    private LinearLayout llPayPassword;
    private LinearLayout llPersonLayout;
    private LinearLayout llSelectedLayout;
    private LinearLayout llTargetLayout;
    private Context mContext;
    private List<Integer> mNumbers;
    private TextView[] mTvPasswords;
    private int notEmptyTvCount;
    private XAlertDialog progressView;
    private int reqId;
    private SegmenteView segRptType;
    private TLRPC.User selectedUser;
    private TLRPC.Chat toChat;
    private TextView tvForgotPassword;
    private TextView tvHongbaoUnit;
    private TextView tvMoneyUnit;
    private TextView tvRpkPromt;
    private TextView tvRptAmountHint;
    private TextView tvRptGreetHint;
    private TextView tvRptMountText;
    private TextView tvRptPersonName;
    private TextView tvRptTargetHint;
    private TextView tvRptTargetText;
    private TextView tvRptTargetUnit;
    private TextView tvRptTypeDesc;
    private TextView tvRptTypeText;
    private TextView tvUserName;
    private int typeRpt;

    public RedpktGroupSendActivity(Bundle args) {
        super(args);
        this.selectedUser = null;
        this.mNumbers = new ArrayList(Arrays.asList(1, 2, 3, 4, 5, 6, 7, 8, 9, -10, 0, -11));
        this.typeRpt = 1001;
        this.reqId = -1;
    }

    public void setAccountInfo(WalletAccountInfo accountInfo) {
        this.accountInfo = accountInfo;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        return true;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        super.onResume();
        getParentActivity().setRequestedOrientation(1);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        super.onFragmentDestroy();
        getParentActivity().setRequestedOrientation(2);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.mContext = context;
        this.fragmentView = LayoutInflater.from(context).inflate(R.layout.activity_hongbao_group_send_layout, (ViewGroup) null, false);
        this.fragmentView.setBackgroundColor(-328966);
        initActionBar();
        initView();
        updateView();
        return this.fragmentView;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    protected void onTransitionAnimationEnd(boolean isOpen, boolean backward) {
        super.onTransitionAnimationEnd(isOpen, backward);
        if (isOpen && this.accountInfo == null) {
            getAccountInfo();
        }
    }

    public void setToChat(TLRPC.Chat toChat) {
        this.toChat = toChat;
    }

    private void initActionBar() {
        this.actionBar.setTitle(LocaleController.getString("redpacket_send", R.string.redpacket_send));
        this.actionBar.setTitleColor(-1);
        this.actionBar.setItemsBackgroundColor(-1, false);
        this.actionBar.setItemsBackgroundColor(-1, true);
        this.actionBar.setItemsColor(-1, false);
        this.actionBar.setItemsColor(-1, true);
        this.actionBar.setBackground(this.gameActionBarBackgroundDrawable);
        this.actionBar.setAllowOverlayTitle(true);
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.getBackButton().setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktGroupSendActivity$yOC8G4RSv-3C5V-XiLvXlnWVhb0
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$initActionBar$0$RedpktGroupSendActivity(view);
            }
        });
    }

    public /* synthetic */ void lambda$initActionBar$0$RedpktGroupSendActivity(View v) {
        finishFragment();
    }

    private void resetAmountPromt() {
        this.tvRpkPromt.setVisibility(8);
        this.tvRptTypeText.setTextColor(-16777216);
        this.etRptAmountEditView.setTextColor(-16777216);
        this.tvHongbaoUnit.setTextColor(-16777216);
    }

    private void resetCountPromt() {
        this.tvRpkPromt.setVisibility(8);
        this.tvRptTargetText.setTextColor(-16777216);
        this.etRptTargetEditView.setTextColor(-16777216);
        this.tvRptTargetUnit.setTextColor(-16777216);
    }

    private void showAmountPromt(String text) {
        this.tvRpkPromt.setVisibility(0);
        this.tvRpkPromt.setText(text);
        this.tvRptTypeText.setTextColor(-109240);
        this.etRptAmountEditView.setTextColor(-109240);
        this.tvHongbaoUnit.setTextColor(-109240);
    }

    private void showCountPromt(String text) {
        this.tvRpkPromt.setVisibility(0);
        if (!TextUtils.isEmpty(text)) {
            this.tvRpkPromt.setText(text);
        }
        this.tvRptTargetText.setTextColor(-109240);
        this.etRptTargetEditView.setTextColor(-109240);
        this.tvRptTargetUnit.setTextColor(-109240);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean updateAmountPromt() {
        int i = this.typeRpt;
        if (i == 1000) {
            String sAmount = this.etRptAmountEditView.getText().toString().trim();
            if (sAmount.length() <= 0) {
                resetAmountPromt();
                return false;
            }
            BigDecimal amount = new BigDecimal(sAmount);
            int ret = amount.compareTo(new BigDecimal("0.01"));
            if (ret < 0) {
                if (BuildVars.EDITION == 0) {
                    showAmountPromt(LocaleController.getString("redpacket_single_limit_personal", R.string.redpacket_single_limit_personal2));
                } else {
                    showAmountPromt(LocaleController.getString("redpacket_single_limit_enterprise", R.string.redpacket_single_limit_enterprise));
                }
                return false;
            }
            int ret2 = amount.compareTo(new BigDecimal(BuildVars.MAX_REDPKT));
            if (ret2 > 0) {
                showAmountPromt(LocaleController.getString(R.string.SingleRedPacketAmoutCannotExceeds) + " " + BuildVars.MAX_REDPKT + LocaleController.getString(R.string.HotCoin));
                return false;
            }
            resetAmountPromt();
            String sCount = this.etRptTargetEditView.getText().toString().trim();
            if (sCount.length() <= 0) {
                resetCountPromt();
                return false;
            }
            int parseInt = Integer.parseInt(sCount);
            if (parseInt < 1 || parseInt > 500) {
                showCountPromt(LocaleController.getString("redpacket_number_not_zero", R.string.redpacket_number_not_zero));
                return false;
            }
            resetCountPromt();
            int ret3 = amount.multiply(new BigDecimal(sCount)).compareTo(new BigDecimal(BuildVars.MAX_REDPKT));
            if (ret3 > 0) {
                showAmountPromt(LocaleController.getString(R.string.SingleRedPacketAmoutCannotExceeds) + " " + BuildVars.MAX_REDPKT + LocaleController.getString(R.string.HotCoin));
                showCountPromt("");
                return false;
            }
            resetAmountPromt();
            resetCountPromt();
            return true;
        }
        if (i == 1001) {
            String sAmount2 = this.etRptAmountEditView.getText().toString().trim();
            if (sAmount2.length() <= 0) {
                resetAmountPromt();
                return false;
            }
            BigDecimal amount2 = new BigDecimal(sAmount2);
            int ret4 = amount2.compareTo(new BigDecimal(BuildVars.MAX_REDPKT));
            if (ret4 > 0) {
                showAmountPromt(LocaleController.getString(R.string.SingleRedPacketAmoutCannotExceeds) + " " + BuildVars.MAX_REDPKT + LocaleController.getString(R.string.HotCoin));
                return false;
            }
            resetAmountPromt();
            String count = this.etRptTargetEditView.getText().toString();
            if (count.length() <= 0) {
                resetCountPromt();
                return false;
            }
            int parseInt2 = Integer.parseInt(count);
            if (parseInt2 < 1 || parseInt2 > 500) {
                showCountPromt(LocaleController.getString("redpacket_number_not_zero", R.string.redpacket_number_not_zero));
                return false;
            }
            resetCountPromt();
            BigDecimal multiply = amount2.divide(new BigDecimal(count), 6, RoundingMode.CEILING);
            int ret5 = multiply.compareTo(new BigDecimal("0.01"));
            if (ret5 < 0) {
                if (BuildVars.EDITION == 0) {
                    showAmountPromt(LocaleController.getString("redpacket_single_limit_personal", R.string.redpacket_single_limit_personal));
                    showCountPromt("");
                } else {
                    showAmountPromt(LocaleController.getString("redpacket_single_limit_enterprise", R.string.redpacket_single_limit_enterprise));
                    showCountPromt("");
                }
                return false;
            }
            resetAmountPromt();
            resetCountPromt();
            return true;
        }
        if (i != 1002) {
            return false;
        }
        String sAmount3 = this.etRptAmountEditView.getText().toString().trim();
        if (sAmount3.length() <= 0) {
            resetAmountPromt();
            return false;
        }
        BigDecimal amount3 = new BigDecimal(sAmount3);
        int ret6 = amount3.compareTo(new BigDecimal("0.01"));
        if (ret6 < 0) {
            showAmountPromt(LocaleController.getString("redpacket_single_limit_personal", R.string.redpacket_single_limit_personal3));
            return false;
        }
        int ret7 = amount3.compareTo(new BigDecimal("100000"));
        if (ret7 > 0) {
            showAmountPromt(LocaleController.getString(R.string.SingleRedPacketAmoutCannotExceeds) + " " + BuildVars.MAX_REDPKT + LocaleController.getString(R.string.HotCoin));
            return false;
        }
        resetAmountPromt();
        return this.selectedUser != null;
    }

    private void updateView() {
        this.etRptAmountEditView.setText("");
        this.etRptGreetEditView.setText("");
        this.etRptTargetEditView.setText("");
        this.selectedUser = null;
        resetAmountPromt();
        resetCountPromt();
        int i = this.typeRpt;
        if (i == 1000) {
            this.tvRptTypeText.setVisibility(0);
            this.ivCoinLogo.setVisibility(4);
            this.tvRptTypeText.setText(LocaleController.getString("repacket_single_amount", R.string.repacket_single_amount));
            this.tvRptAmountHint.setText(LocaleController.getString("redpacket_amount", R.string.redpacket_amount));
        } else if (i == 1001) {
            this.tvRptTypeText.setVisibility(0);
            this.ivCoinLogo.setVisibility(4);
            this.tvRptTypeText.setText(LocaleController.getString("redpacket_total_amount", R.string.redpacket_total_amount));
            this.tvRptAmountHint.setText(LocaleController.getString("redpacket_amount", R.string.redpacket_amount));
        } else if (i == 1002) {
            this.tvRptTypeText.setVisibility(4);
            this.ivCoinLogo.setVisibility(0);
            this.tvRptAmountHint.setText(LocaleController.getString("redpacket_amount", R.string.redpacket_amount));
        }
        int i2 = this.typeRpt;
        if (i2 == 1000) {
            this.tvRptTargetText.setText(LocaleController.getString("redpacket_count", R.string.redpacket_count));
            this.tvRptTargetUnit.setText(LocaleController.getString("redpacket_each", R.string.redpacket_each));
            TextView textView = this.tvRptTargetHint;
            Object[] objArr = new Object[1];
            TLRPC.ChatFull chatFull = this.chatFull;
            objArr[0] = Integer.valueOf(chatFull != null ? chatFull.participants_count : 0);
            textView.setText(LocaleController.formatString("group_person_number", R.string.group_person_number, objArr));
            this.llTargetLayout.setVisibility(0);
            this.llPersonLayout.setVisibility(8);
        } else if (i2 == 1001) {
            this.tvRptTargetText.setText(LocaleController.getString("redpacket_count", R.string.redpacket_count));
            this.tvRptTargetUnit.setText(LocaleController.getString("redpacket_each", R.string.redpacket_each));
            TextView textView2 = this.tvRptTargetHint;
            Object[] objArr2 = new Object[1];
            TLRPC.ChatFull chatFull2 = this.chatFull;
            objArr2[0] = Integer.valueOf(chatFull2 != null ? chatFull2.participants_count : 0);
            textView2.setText(LocaleController.formatString("group_person_number", R.string.group_person_number, objArr2));
            this.llTargetLayout.setVisibility(0);
            this.llPersonLayout.setVisibility(8);
        } else if (i2 == 1002) {
            this.tvRptTargetText.setText(LocaleController.getString("redpacket_recipients", R.string.redpacket_recipients));
            this.tvRptTargetHint.setText(LocaleController.getString("redpacket_choose_person", R.string.redpacket_choose_person));
            this.tvRptTargetUnit.setText(LocaleController.getString("redpacket_each", R.string.redpacket_each));
            this.llTargetLayout.setVisibility(8);
            this.llPersonLayout.setVisibility(0);
            this.llSelectedLayout.setVisibility(8);
            this.tvRptPersonName.setVisibility(0);
        }
        int i3 = this.typeRpt;
        if (i3 == 1000) {
            this.tvRptTypeDesc.setText("");
        } else if (i3 == 1001) {
            this.tvRptTypeDesc.setText("");
        } else if (i3 == 1002) {
            this.tvRptTypeDesc.setText(LocaleController.getString("redpacket_special", R.string.redpacket_special));
        }
    }

    private void initView() {
        this.segRptType = (SegmenteView) this.fragmentView.findViewById(R.attr.segRptType);
        this.llPersonLayout = (LinearLayout) this.fragmentView.findViewById(R.attr.llPersonLayout);
        this.llTargetLayout = (LinearLayout) this.fragmentView.findViewById(R.attr.llTargetLayout);
        this.llSelectedLayout = (LinearLayout) this.fragmentView.findViewById(R.attr.ll_selected_layout);
        this.bivUserSelected = (BackupImageView) this.fragmentView.findViewById(R.attr.iv_user_selected);
        this.tvUserName = (TextView) this.fragmentView.findViewById(R.attr.tv_user_name);
        this.tvRptMountText = (TextView) this.fragmentView.findViewById(R.attr.tvRptMountText);
        this.ivCoinLogo = (ImageView) this.fragmentView.findViewById(R.attr.ivCoinLogo);
        this.tvRptTypeText = (TextView) this.fragmentView.findViewById(R.attr.tvRptTypeText);
        this.etRptAmountEditView = (EditText) this.fragmentView.findViewById(R.attr.etRptAmountEditView);
        this.tvRptAmountHint = (TextView) this.fragmentView.findViewById(R.attr.tvRptAmountHint);
        this.tvRpkPromt = (TextView) this.fragmentView.findViewById(R.attr.tvRpkPromt);
        this.tvHongbaoUnit = (TextView) this.fragmentView.findViewById(R.attr.tvHongbaoUnit);
        this.tvRptTargetText = (TextView) this.fragmentView.findViewById(R.attr.tvRptTargetText);
        this.etRptTargetEditView = (EditText) this.fragmentView.findViewById(R.attr.etRptTargetEditView);
        this.tvRptTargetHint = (TextView) this.fragmentView.findViewById(R.attr.tvRptTargetHint);
        this.tvRptTargetUnit = (TextView) this.fragmentView.findViewById(R.attr.tvRptTargetUnit);
        this.tvRptPersonName = (TextView) this.fragmentView.findViewById(R.attr.tvRptPersonName);
        this.tvRptTypeDesc = (TextView) this.fragmentView.findViewById(R.attr.tvRptTypeDesc);
        this.etRptGreetEditView = (EditText) this.fragmentView.findViewById(R.attr.etRptGreetEditView);
        this.tvRptGreetHint = (TextView) this.fragmentView.findViewById(R.attr.tvRptGreetHint);
        this.btnRptSend = (Button) this.fragmentView.findViewById(R.attr.btnRptSend);
        this.tvMoneyUnit = (TextView) this.fragmentView.findViewById(R.attr.tvMoneyUnit);
        this.tvRpkPromt.setVisibility(8);
        this.segRptType.setOnSelectionChangedListener(new SegmenteView.OnSelectionChangedListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktGroupSendActivity$52lnbdT_Jbwg9r3Qdi6zVQCtZYQ
            @Override // im.uwrkaxlmjj.ui.hviews.SegmenteView.OnSelectionChangedListener
            public final void onItemSelected(int i) {
                this.f$0.lambda$initView$1$RedpktGroupSendActivity(i);
            }
        });
        this.tvHongbaoUnit.setText(LocaleController.getString(R.string.UnitCNY));
        this.tvMoneyUnit.setText(LocaleController.getString(R.string.UnitCNY));
        String[] items = {LocaleController.getString("redpacket_group_random", R.string.redpacket_group_random), LocaleController.getString("redpacket_group_common", R.string.redpacket_group_common), LocaleController.getString("redpacket_group_exclusive", R.string.redpacket_group_exclusive)};
        String[] values = {"0", "1", "2"};
        try {
            this.segRptType.setItems(items, values);
        } catch (Exception e) {
            e.printStackTrace();
        }
        this.tvRptGreetHint.setText(LocaleController.getString("redpacket_greetings_tip", R.string.redpacket_greetings_tip));
        this.etRptAmountEditView.setFilters(new InputFilter[]{new EditInputFilter()});
        this.etRptAmountEditView.addTextChangedListener(new TextWatcher() { // from class: im.uwrkaxlmjj.ui.hui.packet.RedpktGroupSendActivity.1
            @Override // android.text.TextWatcher
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            @Override // android.text.TextWatcher
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                RedpktGroupSendActivity.this.tvRptAmountHint.setText(s.length() > 0 ? "" : LocaleController.getString("redpacket_amount", R.string.redpacket_amount));
                RedpktGroupSendActivity.this.updateTotal();
                if (RedpktGroupSendActivity.this.updateAmountPromt()) {
                    RedpktGroupSendActivity.this.btnRptSend.setEnabled(true);
                } else {
                    RedpktGroupSendActivity.this.btnRptSend.setEnabled(false);
                }
            }

            @Override // android.text.TextWatcher
            public void afterTextChanged(Editable s) {
            }
        });
        this.etRptTargetEditView.setFilters(new InputFilter[]{new InputNumberFilter(-1)});
        this.etRptTargetEditView.addTextChangedListener(new TextWatcher() { // from class: im.uwrkaxlmjj.ui.hui.packet.RedpktGroupSendActivity.2
            @Override // android.text.TextWatcher
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            @Override // android.text.TextWatcher
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                String string;
                TextView textView = RedpktGroupSendActivity.this.tvRptTargetHint;
                if (s.length() > 0) {
                    string = "";
                } else {
                    Object[] objArr = new Object[1];
                    objArr[0] = Integer.valueOf(RedpktGroupSendActivity.this.chatFull != null ? RedpktGroupSendActivity.this.chatFull.participants_count : 0);
                    string = LocaleController.formatString("group_person_number", R.string.group_person_number, objArr);
                }
                textView.setText(string);
                RedpktGroupSendActivity.this.updateTotal();
                if (RedpktGroupSendActivity.this.updateAmountPromt()) {
                    RedpktGroupSendActivity.this.btnRptSend.setEnabled(true);
                } else {
                    RedpktGroupSendActivity.this.btnRptSend.setEnabled(false);
                }
            }

            @Override // android.text.TextWatcher
            public void afterTextChanged(Editable s) {
            }
        });
        this.etRptGreetEditView.addTextChangedListener(new TextWatcher() { // from class: im.uwrkaxlmjj.ui.hui.packet.RedpktGroupSendActivity.3
            @Override // android.text.TextWatcher
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            @Override // android.text.TextWatcher
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                if (s.length() > 0) {
                    RedpktGroupSendActivity.this.tvRptGreetHint.setText("");
                } else {
                    RedpktGroupSendActivity.this.tvRptGreetHint.setText(LocaleController.getString("redpacket_greetings_tip", R.string.redpacket_greetings_tip));
                }
            }

            @Override // android.text.TextWatcher
            public void afterTextChanged(Editable s) {
            }
        });
        this.llPersonLayout.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktGroupSendActivity$KtZSwU3z7bAmkc7b_TJvgz1inaw
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$initView$3$RedpktGroupSendActivity(view);
            }
        });
        this.btnRptSend.setEnabled(false);
        this.btnRptSend.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktGroupSendActivity$31LCPtSGYBF45LKcT5_LGsnjqNM
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$initView$4$RedpktGroupSendActivity(view);
            }
        });
        this.tvRptTargetHint.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText7));
        this.tvRptAmountHint.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText7));
        this.tvRptPersonName.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText7));
        this.tvRptGreetHint.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText7));
        this.btnRptSend.setText(LocaleController.getString(R.string.redpacket_add_money));
        ((TextView) this.fragmentView.findViewById(R.attr.tvTimeoutDesc)).setText(LocaleController.getString(R.string.RedPacketsWillReturnWhenNotReceivedIn24Hours));
    }

    public /* synthetic */ void lambda$initView$1$RedpktGroupSendActivity(int checkedId) {
        int parseInt = Integer.parseInt(this.segRptType.getChecked());
        if (parseInt == 0) {
            this.typeRpt = 1001;
        } else if (parseInt == 1) {
            this.typeRpt = 1000;
        } else if (parseInt == 2) {
            this.typeRpt = 1002;
        }
        updateView();
    }

    public /* synthetic */ void lambda$initView$3$RedpktGroupSendActivity(View v) {
        SelecteContactsActivity selectedContactActivity = new SelecteContactsActivity(null);
        selectedContactActivity.setChatInfo(this.chatFull);
        selectedContactActivity.setDelegate(new SelecteContactsActivity.ContactsActivityDelegate() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktGroupSendActivity$hvHy7xCxrQDRha43rGSVp_xwpxU
            @Override // im.uwrkaxlmjj.ui.hui.packet.SelecteContactsActivity.ContactsActivityDelegate
            public final void didSelectContact(TLRPC.User user) {
                this.f$0.lambda$null$2$RedpktGroupSendActivity(user);
            }
        });
        presentFragment(selectedContactActivity);
    }

    public /* synthetic */ void lambda$null$2$RedpktGroupSendActivity(TLRPC.User user) {
        if (user != null) {
            this.selectedUser = user;
            if (updateAmountPromt()) {
                this.btnRptSend.setEnabled(true);
            } else {
                this.btnRptSend.setEnabled(false);
            }
            this.llSelectedLayout.setVisibility(0);
            this.tvRptPersonName.setVisibility(8);
            AvatarDrawable avatarDrawable = new AvatarDrawable();
            avatarDrawable.setTextSize(AndroidUtilities.dp(16.0f));
            avatarDrawable.setInfo(user);
            this.bivUserSelected.setRoundRadius(AndroidUtilities.dp(32.0f));
            this.bivUserSelected.getImageReceiver().setCurrentAccount(this.currentAccount);
            this.bivUserSelected.setImage(ImageLocation.getForUser(user, false), "50_50", avatarDrawable, user);
            this.tvUserName.setText(user.first_name);
        }
    }

    public /* synthetic */ void lambda$initView$4$RedpktGroupSendActivity(View v) {
        createPayAlert(this.accountInfo.getCashAmount() / 100.0d);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateTotal() {
        int i = this.typeRpt;
        if (i == 1000) {
            if (TextUtils.isEmpty(this.etRptAmountEditView.getText())) {
                this.tvRptMountText.setText("0.00");
                return;
            }
            if (TextUtils.isEmpty(this.etRptTargetEditView.getText())) {
                this.tvRptMountText.setText("0.00");
                return;
            }
            String strSingal = this.etRptAmountEditView.getText().toString().trim();
            String strCount = this.etRptTargetEditView.getText().toString().trim();
            BigDecimal bigSingal = new BigDecimal(strSingal);
            BigDecimal bitCount = new BigDecimal(strCount);
            this.tvRptMountText.setText(DataTools.format2Decimals(bigSingal.multiply(bitCount).toString()));
            return;
        }
        if (i == 1001) {
            if (TextUtils.isEmpty(this.etRptAmountEditView.getText())) {
                this.tvRptMountText.setText("0.00");
                return;
            } else {
                this.tvRptMountText.setText(DataTools.format2Decimals(this.etRptAmountEditView.getText().toString().trim()));
                return;
            }
        }
        if (i == 1002) {
            if (TextUtils.isEmpty(this.etRptAmountEditView.getText())) {
                this.tvRptMountText.setText("0.00");
            } else {
                this.tvRptMountText.setText(DataTools.format2Decimals(this.etRptAmountEditView.getText().toString().trim()));
            }
        }
    }

    private void createPayAlert(double balance) {
        BottomSheet.Builder builder = new BottomSheet.Builder(getParentActivity());
        builder.setApplyTopPadding(false);
        builder.setApplyBottomPadding(false);
        View sheet = LayoutInflater.from(getParentActivity()).inflate(R.layout.layout_hongbao_pay_pwd, (ViewGroup) null, false);
        builder.setCustomView(sheet);
        ImageView ivAlertClose = (ImageView) sheet.findViewById(R.attr.ivAlertClose);
        ivAlertClose.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktGroupSendActivity$_glUUOd4DtGui2U-JYc7-C2cIu8
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$createPayAlert$5$RedpktGroupSendActivity(view);
            }
        });
        TextView tvTitle = (TextView) sheet.findViewById(R.attr.tvTitle);
        if (this.typeRpt == 1002) {
            tvTitle.setText(LocaleController.getString(R.string.redpacket_group_exclusive));
        } else {
            tvTitle.setText(String.format("%s" + LocaleController.getString(R.string.redpacket_each) + LocaleController.getString(R.string.RedPacket) + LocaleController.getString(R.string.Comma) + LocaleController.getString(R.string.HotCoinTotal), this.etRptTargetEditView.getText().toString().trim()));
        }
        TextView tvShowMoneyView = (TextView) sheet.findViewById(R.attr.tvShowMoneyView);
        tvShowMoneyView.setTextColor(-109240);
        tvShowMoneyView.setText(DataTools.format2Decimals(this.tvRptMountText.getText().toString().trim()));
        TextView tvMoneyUnit = (TextView) sheet.findViewById(R.attr.tvMoneyUnit);
        TextView tvPayMode = (TextView) sheet.findViewById(R.attr.tvPayMode);
        tvPayMode.setTextColor(-6710887);
        tvPayMode.setText(LocaleController.getString(R.string.HotCoinPay));
        TextView tvBlance = (TextView) sheet.findViewById(R.attr.tvBlance);
        SpanUtils spanTvBalance = SpanUtils.with(tvBlance);
        spanTvBalance.setVerticalAlign(2).append(LocaleController.getString(R.string.friendscircle_publish_remain)).setForegroundColor(-6710887).append(" (").setForegroundColor(-6710887);
        spanTvBalance.append(String.format("%.2f", Double.valueOf(balance)));
        tvMoneyUnit.setText(LocaleController.getString(R.string.UnitCNY));
        spanTvBalance.setForegroundColor(-16777216).append(SQLBuilder.PARENTHESES_RIGHT).setForegroundColor(-6710887).create();
        TextView textView = (TextView) sheet.findViewById(R.attr.tvForgotPassword);
        this.tvForgotPassword = textView;
        textView.setText(LocaleController.getString(R.string.PasswordRecovery));
        this.tvForgotPassword.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktGroupSendActivity$06JYxGcUWCb8f8HSr-jmj1vpbKc
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                RedpktGroupSendActivity.lambda$createPayAlert$6(view);
            }
        });
        this.llPayPassword = (LinearLayout) sheet.findViewById(R.attr.ll_pay_password);
        TextView[] textViewArr = new TextView[6];
        this.mTvPasswords = textViewArr;
        textViewArr[0] = (TextView) sheet.findViewById(R.attr.tv_password_1);
        this.mTvPasswords[1] = (TextView) sheet.findViewById(R.attr.tv_password_2);
        this.mTvPasswords[2] = (TextView) sheet.findViewById(R.attr.tv_password_3);
        this.mTvPasswords[3] = (TextView) sheet.findViewById(R.attr.tv_password_4);
        this.mTvPasswords[4] = (TextView) sheet.findViewById(R.attr.tv_password_5);
        this.mTvPasswords[5] = (TextView) sheet.findViewById(R.attr.tv_password_6);
        GridView gvKeyboard = (GridView) sheet.findViewById(R.attr.gvKeyboard);
        gvKeyboard.setAdapter((ListAdapter) new MyAdapter());
        gvKeyboard.setOnItemClickListener(new AdapterView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktGroupSendActivity$c3USoJRMhTqz4nfYoql3Ucl9-rc
            @Override // android.widget.AdapterView.OnItemClickListener
            public final void onItemClick(AdapterView adapterView, View view, int i, long j) {
                this.f$0.lambda$createPayAlert$7$RedpktGroupSendActivity(adapterView, view, i, j);
            }
        });
        Dialog dialog = showDialog(builder.create());
        dialog.setOnDismissListener(new DialogInterface.OnDismissListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktGroupSendActivity$A_Eb9j94JQdniHL3QDV5QiWcHz0
            @Override // android.content.DialogInterface.OnDismissListener
            public final void onDismiss(DialogInterface dialogInterface) {
                this.f$0.lambda$createPayAlert$8$RedpktGroupSendActivity(dialogInterface);
            }
        });
    }

    public /* synthetic */ void lambda$createPayAlert$5$RedpktGroupSendActivity(View v) {
        dismissCurrentDialog();
    }

    static /* synthetic */ void lambda$createPayAlert$6(View v) {
    }

    public /* synthetic */ void lambda$createPayAlert$7$RedpktGroupSendActivity(AdapterView parent, View view, int position, long id) {
        int i = 0;
        if (position < 9 || position == 10) {
            int i2 = this.notEmptyTvCount;
            TextView[] textViewArr = this.mTvPasswords;
            if (i2 == textViewArr.length) {
                return;
            }
            int length = textViewArr.length;
            int i3 = 0;
            while (true) {
                if (i3 >= length) {
                    break;
                }
                TextView textView = textViewArr[i3];
                if (!TextUtils.isEmpty(textView.getText())) {
                    i3++;
                } else {
                    textView.setText(String.valueOf(this.mNumbers.get(position)));
                    this.notEmptyTvCount++;
                    break;
                }
            }
            if (this.notEmptyTvCount == this.mTvPasswords.length) {
                StringBuilder password = new StringBuilder();
                TextView[] textViewArr2 = this.mTvPasswords;
                int length2 = textViewArr2.length;
                while (i < length2) {
                    String text = textViewArr2[i].getText().toString();
                    if (!TextUtils.isEmpty(text)) {
                        password.append(text);
                    }
                    i++;
                }
                String encrypt = AesUtils.encrypt(password.toString().trim());
                int total = new BigDecimal(this.tvRptMountText.getText().toString().trim()).multiply(new BigDecimal("100")).intValue();
                String count = this.etRptTargetEditView.getText().toString().trim();
                sendRedpacket(String.valueOf(total), encrypt, this.toChat.id, this.toChat.title, this.typeRpt == 1002 ? 1 : Integer.parseInt(count));
                return;
            }
            return;
        }
        if (position == 11) {
            if (this.notEmptyTvCount == this.mTvPasswords.length) {
                this.tvForgotPassword.setText(LocaleController.getString("PasswordRecovery", R.string.PasswordRecovery));
                this.tvForgotPassword.setTextColor(-14250753);
                this.tvForgotPassword.setEnabled(true);
                this.llPayPassword.setBackgroundResource(R.drawable.shape_pay_password_bg);
                this.llPayPassword.setDividerDrawable(getParentActivity().getResources().getDrawable(R.drawable.shape_pay_password_divider));
                TextView[] textViewArr3 = this.mTvPasswords;
                int length3 = textViewArr3.length;
                while (i < length3) {
                    TextView mTvPassword = textViewArr3[i];
                    mTvPassword.setTextColor(-16777216);
                    i++;
                }
            }
            for (int i4 = this.mTvPasswords.length - 1; i4 >= 0; i4--) {
                if (!TextUtils.isEmpty(this.mTvPasswords[i4].getText())) {
                    this.mTvPasswords[i4].setText((CharSequence) null);
                    this.notEmptyTvCount--;
                    return;
                }
            }
        }
    }

    public /* synthetic */ void lambda$createPayAlert$8$RedpktGroupSendActivity(DialogInterface dialog1) {
        this.notEmptyTvCount = 0;
    }

    private void finish() {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$-J2LfW_byEfyQR_fttmlHOOBBoc
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.finishFragment();
            }
        });
    }

    private void getAccountInfo() {
        this.progressView = new XAlertDialog(getParentActivity(), 5);
        TLRPCWallet.TL_getPaymentAccountInfo req = new TLRPCWallet.TL_getPaymentAccountInfo();
        this.reqId = getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktGroupSendActivity$8SGQlglcH0l4lmPAlz8wSa1KKto
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$getAccountInfo$24$RedpktGroupSendActivity(tLObject, tL_error);
            }
        });
        this.progressView.setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktGroupSendActivity$DPP4d9ZFY5RlZvxmiD4Y18Da7Pc
            @Override // android.content.DialogInterface.OnCancelListener
            public final void onCancel(DialogInterface dialogInterface) {
                this.f$0.lambda$getAccountInfo$25$RedpktGroupSendActivity(dialogInterface);
            }
        });
        try {
            this.progressView.show();
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public /* synthetic */ void lambda$getAccountInfo$24$RedpktGroupSendActivity(TLObject response, TLRPC.TL_error error) {
        if (error != null) {
            this.progressView.dismiss();
            WalletDialogUtil.showConfirmBtnWalletDialog((Object) this, (CharSequence) WalletErrorUtil.getErrorDescription(LocaleController.formatString("SystemIsBusyAndTryAgainLater", R.string.SystemIsBusyAndTryAgainLater, new Object[0]), error.text), true, new DialogInterface.OnDismissListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktGroupSendActivity$mkdm3fUTxKouS0984CnAqFcC590
                @Override // android.content.DialogInterface.OnDismissListener
                public final void onDismiss(DialogInterface dialogInterface) {
                    this.f$0.lambda$null$9$RedpktGroupSendActivity(dialogInterface);
                }
            });
            return;
        }
        this.progressView.dismiss();
        if (response instanceof TLRPCWallet.TL_paymentAccountInfoNotExist) {
            WalletDialogUtil.showWalletDialog(this, "", LocaleController.formatString("AccountInfoNotCompleted", R.string.AccountInfoNotCompleted, LocaleController.getString(R.string.SendRedPackets), LocaleController.getString(R.string.SendRedPackets)), LocaleController.getString("Close", R.string.Close), LocaleController.getString("GoToWalletCenter", R.string.GoToWalletCenter), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktGroupSendActivity$GzgLWYJPAKqEYN78mepDhCs1m3Y
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    this.f$0.lambda$null$10$RedpktGroupSendActivity(dialogInterface, i);
                }
            }, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktGroupSendActivity$Hr7ZwZ9MC-iDP_v-SeolNDo_ICA
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktGroupSendActivity$P4xxWoV1VqXJr6yhURTSyLIm4yA
                        @Override // java.lang.Runnable
                        public final void run() {
                            RedpktGroupSendActivity.lambda$null$11();
                        }
                    });
                }
            }, new DialogInterface.OnDismissListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktGroupSendActivity$TQNGGZPQCGdn4crW00luat43Xyk
                @Override // android.content.DialogInterface.OnDismissListener
                public final void onDismiss(DialogInterface dialogInterface) {
                    this.f$0.lambda$null$13$RedpktGroupSendActivity(dialogInterface);
                }
            });
            return;
        }
        TLApiModel<WalletAccountInfo> model = TLJsonResolve.parse(response, (Class<?>) WalletAccountInfo.class);
        if (model.isSuccess()) {
            WalletAccountInfo walletAccountInfo = model.model;
            this.accountInfo = walletAccountInfo;
            WalletConfigBean.setWalletAccountInfo(walletAccountInfo);
            WalletConfigBean.setConfigValue(model.model.getRiskList());
            if (!this.accountInfo.hasNormalAuth()) {
                WalletDialogUtil.showWalletDialog(this, "", LocaleController.getString("BasicAuthNor", R.string.BasicAuthNor), LocaleController.getString("Close", R.string.Close), LocaleController.getString("GoToAuth", R.string.GoToAuth), null, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktGroupSendActivity$nSbJyECvmrxanCFhjTx0pe5dVuw
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i) {
                        RedpktGroupSendActivity.lambda$null$14(dialogInterface, i);
                    }
                }, null);
                return;
            } else if (!this.accountInfo.hasBindBank()) {
                WalletDialogUtil.showWalletDialog(this, "", LocaleController.getString("BankBindNor", R.string.BankBindNor), LocaleController.getString("Close", R.string.Close), LocaleController.getString("GoToBind", R.string.GoToBind), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktGroupSendActivity$NqTKSPO0LnQpav8v6zbmSl3ixtg
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i) {
                        this.f$0.lambda$null$15$RedpktGroupSendActivity(dialogInterface, i);
                    }
                }, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktGroupSendActivity$SQcgbmFZsgiL_vPh_dOIISPKtws
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i) {
                        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktGroupSendActivity$e2epKvnjzuSEfa1-Q0n9vpyq9E8
                            @Override // java.lang.Runnable
                            public final void run() {
                                RedpktGroupSendActivity.lambda$null$16();
                            }
                        });
                    }
                }, new DialogInterface.OnDismissListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktGroupSendActivity$a3arEw_Qkrz7wmBGT4l1CVB5gbc
                    @Override // android.content.DialogInterface.OnDismissListener
                    public final void onDismiss(DialogInterface dialogInterface) {
                        this.f$0.lambda$null$18$RedpktGroupSendActivity(dialogInterface);
                    }
                });
                return;
            } else {
                if (!this.accountInfo.hasPaypassword()) {
                    WalletDialogUtil.showWalletDialog(this, "", LocaleController.getString("PayPasswordNor", R.string.PayPasswordNor), LocaleController.getString("Close", R.string.Close), LocaleController.getString("redpacket_goto_set", R.string.redpacket_goto_set), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktGroupSendActivity$5vPpdiyBJerPsDHWFx5bgjaX4J0
                        @Override // android.content.DialogInterface.OnClickListener
                        public final void onClick(DialogInterface dialogInterface, int i) {
                            this.f$0.lambda$null$19$RedpktGroupSendActivity(dialogInterface, i);
                        }
                    }, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktGroupSendActivity$HiW7BENWMjHUgCd4oR8EKrsQx9M
                        @Override // android.content.DialogInterface.OnClickListener
                        public final void onClick(DialogInterface dialogInterface, int i) {
                            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktGroupSendActivity$w4cEvAPdOTe8g4JIBXnxUJJQn60
                                @Override // java.lang.Runnable
                                public final void run() {
                                    RedpktGroupSendActivity.lambda$null$20();
                                }
                            });
                        }
                    }, new DialogInterface.OnDismissListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktGroupSendActivity$U3GQVmSKgnWq0MbWE_5SkxJunso
                        @Override // android.content.DialogInterface.OnDismissListener
                        public final void onDismiss(DialogInterface dialogInterface) {
                            this.f$0.lambda$null$22$RedpktGroupSendActivity(dialogInterface);
                        }
                    });
                    return;
                }
                return;
            }
        }
        WalletDialogUtil.showConfirmBtnWalletDialog((Object) this, (CharSequence) WalletErrorUtil.getErrorDescription(LocaleController.formatString("SystemIsBusyAndTryAgainLater", R.string.SystemIsBusyAndTryAgainLater, new Object[0]), model.message), true, new DialogInterface.OnDismissListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktGroupSendActivity$giMr30wAISNiOdQcdDe8IXA36Z4
            @Override // android.content.DialogInterface.OnDismissListener
            public final void onDismiss(DialogInterface dialogInterface) {
                this.f$0.lambda$null$23$RedpktGroupSendActivity(dialogInterface);
            }
        });
    }

    public /* synthetic */ void lambda$null$9$RedpktGroupSendActivity(DialogInterface dialog) {
        finish();
    }

    public /* synthetic */ void lambda$null$10$RedpktGroupSendActivity(DialogInterface dialogInterface, int i) {
        finish();
    }

    static /* synthetic */ void lambda$null$11() {
    }

    public /* synthetic */ void lambda$null$13$RedpktGroupSendActivity(DialogInterface dialog) {
        finish();
    }

    static /* synthetic */ void lambda$null$14(DialogInterface dialogInterface, int i) {
    }

    public /* synthetic */ void lambda$null$15$RedpktGroupSendActivity(DialogInterface dialogInterface, int i) {
        finish();
    }

    static /* synthetic */ void lambda$null$16() {
    }

    public /* synthetic */ void lambda$null$18$RedpktGroupSendActivity(DialogInterface dialog) {
        finish();
    }

    public /* synthetic */ void lambda$null$19$RedpktGroupSendActivity(DialogInterface dialogInterface, int i) {
        finish();
    }

    static /* synthetic */ void lambda$null$20() {
    }

    public /* synthetic */ void lambda$null$22$RedpktGroupSendActivity(DialogInterface dialog) {
        finish();
    }

    public /* synthetic */ void lambda$null$23$RedpktGroupSendActivity(DialogInterface dialog) {
        finish();
    }

    public /* synthetic */ void lambda$getAccountInfo$25$RedpktGroupSendActivity(DialogInterface dialog) {
        getConnectionsManager().cancelRequest(this.reqId, true);
        finish();
    }

    private void sendRedpacket(String total, String pwd, int chatId, String chatName, int count) {
        TLRPC.User user;
        TLRPCRedpacket.CL_messages_sendRptTransfer req = new TLRPCRedpacket.CL_messages_sendRptTransfer();
        req.flags = 3;
        req.trans = 0;
        req.type = 0;
        TLRPC.InputPeer inputPeer = new TLRPC.TL_inputPeerChannel();
        inputPeer.channel_id = this.toChat.id;
        inputPeer.access_hash = this.toChat.access_hash;
        req.peer = inputPeer;
        RepacketRequest bean = new RepacketRequest();
        bean.setOutTradeNo("android_" + getUserConfig().clientUserId + StringUtils.getRandomString(16) + getConnectionsManager().getCurrentTime());
        bean.setNonceStr(StringUtils.getRandomString(32));
        bean.setBody(String.format(LocaleController.formatString("redpacket_send_in_group", R.string.redpacket_send_in_group, chatName), new Object[0]));
        bean.setDetail("");
        bean.setAttach("");
        bean.setTotalFee(total);
        bean.setTradeType("1");
        bean.setRemarks(TextUtils.isEmpty(this.etRptGreetEditView.getText()) ? "" : this.etRptGreetEditView.getText().toString().trim());
        bean.setInitiator(String.valueOf(getUserConfig().getClientUserId()));
        bean.setPayPassWord(pwd);
        bean.setBusinessKey(UnifyBean.BUSINESS_KEY_REDPACKET);
        bean.setRecipient(String.valueOf(chatId));
        bean.setVersion("1");
        int i = this.typeRpt;
        if (i == 1000) {
            bean.setRedType("1");
            bean.setGrantType("0");
        } else if (i == 1001) {
            bean.setRedType("1");
            bean.setGrantType("1");
        } else if (i == 1002) {
            bean.setRedType("2");
            bean.setGrantType("0");
        }
        bean.setGroups(String.valueOf(chatId));
        bean.setGroupsName(chatName);
        if (this.typeRpt == 1000) {
            String singal = new BigDecimal(this.etRptAmountEditView.getText().toString().trim()).multiply(new BigDecimal("100")).toString();
            bean.setFixedAmount(singal);
        } else {
            bean.setFixedAmount(total);
        }
        if (this.typeRpt == 1002 && (user = this.selectedUser) != null) {
            bean.setRecipient(String.valueOf(user.id));
        }
        bean.setNumber(Integer.valueOf(count));
        TLRPC.TL_dataJSON data = new TLRPC.TL_dataJSON();
        data.data = new Gson().toJson(bean);
        req.redPkg = data;
        req.random_id = getSendMessagesHelper().getNextRandomId();
        this.progressView = new XAlertDialog(getParentActivity(), 5);
        this.reqId = getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktGroupSendActivity$0vIBYO0eGT1kNlXi2KjL-gxqp1w
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$sendRedpacket$35$RedpktGroupSendActivity(tLObject, tL_error);
            }
        });
        this.progressView.setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktGroupSendActivity$P9yL7MJzOPybQ3wXB9c6jijjfFY
            @Override // android.content.DialogInterface.OnCancelListener
            public final void onCancel(DialogInterface dialogInterface) {
                this.f$0.lambda$sendRedpacket$36$RedpktGroupSendActivity(dialogInterface);
            }
        });
        try {
            this.progressView.show();
            this.progressView.setLoadingText(LocaleController.getString(R.string.Sending));
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public /* synthetic */ void lambda$sendRedpacket$35$RedpktGroupSendActivity(final TLObject response, final TLRPC.TL_error error) {
        this.progressView.dismiss();
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktGroupSendActivity$X1JwOFixtQGjCg_KNljz4krYgts
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$34$RedpktGroupSendActivity(error, response);
            }
        });
    }

    public /* synthetic */ void lambda$null$34$RedpktGroupSendActivity(TLRPC.TL_error error, TLObject response) {
        if (error != null) {
            if (error.text == null) {
                error.text = "";
            }
            error.text = error.text.replace(ShellAdbUtils.COMMAND_LINE_END, "");
            if (error.text.contains("ACCOUNT_PASSWORD_IN_MINUTES,ERROR_TIMES,WILL_BE_FROZEN")) {
                String[] split = error.text.split("_");
                String str = split[split.length - 2];
                final String time = split[split.length - 1];
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktGroupSendActivity$cSXZ3K00gRKr1yJlr5_6PWCB5x0
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$26$RedpktGroupSendActivity(time);
                    }
                });
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktGroupSendActivity$ufv966FMqGGOOgegqp0gKQputj4
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$27$RedpktGroupSendActivity();
                    }
                }, 2500L);
                return;
            }
            if ("NOT_SUFFICIENT_FUNDS".equals(error.text)) {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktGroupSendActivity$Tc7Lmgi-BeNHozhVP8IjtGXNjWg
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$31$RedpktGroupSendActivity();
                    }
                });
                return;
            }
            if ("ACCOUNT_HAS_BEEN_FROZEN_CODE".equals(error.text) || "PAY_PASSWORD_MAX_ACCOUNT_FROZEN".equals(error.text)) {
                dismissCurrentDialog();
                WalletDialogUtil.showWalletDialog(this, "", WalletErrorUtil.getErrorDescription(error.text), LocaleController.getString("Confirm", R.string.Confirm), LocaleController.getString("ContactCustomerService", R.string.ContactCustomerService), null, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktGroupSendActivity$WpSUzyt1_dByXfnrelEm6XVIBAk
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i) {
                        this.f$0.lambda$null$32$RedpktGroupSendActivity(dialogInterface, i);
                    }
                }, null);
                return;
            } else if (error.text.contains("EXCEED_RED_PACKET_ONCE_MAX_MONEY")) {
                dismissCurrentDialog();
                WalletDialogUtil.showSingleBtnWalletDialog(this, WalletErrorUtil.getErrorDescription(error.text), LocaleController.getString("Confirm", R.string.Confirm), false, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktGroupSendActivity$uC22A5706OmxU64Bnvei1_ONpG8
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i) {
                        this.f$0.lambda$null$33$RedpktGroupSendActivity(dialogInterface, i);
                    }
                }, null);
                return;
            } else {
                dismissCurrentDialog();
                WalletErrorUtil.parseErrorDialog(this, error.text);
                return;
            }
        }
        if (response instanceof TLRPC.Updates) {
            TLRPC.Updates updates = (TLRPC.Updates) response;
            getMessagesController().processUpdates(updates, false);
            finishFragment();
        }
    }

    public /* synthetic */ void lambda$null$26$RedpktGroupSendActivity(String time) {
        this.tvForgotPassword.setText(LocaleController.formatString("PassswordErrorText", R.string.PassswordErrorText, time));
        this.tvForgotPassword.setTextColor(-109240);
        this.tvForgotPassword.setEnabled(false);
        this.llPayPassword.setBackgroundResource(R.drawable.shape_pay_password_error_bg);
        this.llPayPassword.setDividerDrawable(getParentActivity().getResources().getDrawable(R.drawable.shape_pay_password_error_divider));
        for (TextView mTvPassword : this.mTvPasswords) {
            mTvPassword.setTextColor(-109240);
        }
    }

    public /* synthetic */ void lambda$null$27$RedpktGroupSendActivity() {
        this.tvForgotPassword.setText(LocaleController.getString("PasswordRecovery", R.string.PasswordRecovery));
        this.tvForgotPassword.setTextColor(-14250753);
        this.tvForgotPassword.setEnabled(true);
        this.llPayPassword.setBackgroundResource(R.drawable.shape_pay_password_bg);
        this.llPayPassword.setDividerDrawable(getParentActivity().getResources().getDrawable(R.drawable.shape_pay_password_divider));
        for (TextView mTvPassword : this.mTvPasswords) {
            mTvPassword.setText((CharSequence) null);
            mTvPassword.setTextColor(-16777216);
            this.notEmptyTvCount = 0;
        }
    }

    public /* synthetic */ void lambda$null$31$RedpktGroupSendActivity() {
        dismissCurrentDialog();
        WalletDialog walletDialog = WalletDialogUtil.showWalletDialog(this, "", LocaleController.getString("BalanceIsNotEnough", R.string.BalanceIsNotEnough), LocaleController.getString(R.string.ChangeHotCoinCount), LocaleController.getString(R.string.ChargeAmount), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktGroupSendActivity$rTwEofCrDj0dLJSDGJFRI9cjzoc
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                this.f$0.lambda$null$29$RedpktGroupSendActivity(dialogInterface, i);
            }
        }, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktGroupSendActivity$y86tQYpOED-5yE8ie8fDOtrhQrM
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                RedpktGroupSendActivity.lambda$null$30(dialogInterface, i);
            }
        }, null);
        walletDialog.getNegativeButton().setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlueText));
    }

    public /* synthetic */ void lambda$null$29$RedpktGroupSendActivity(DialogInterface dialogInterface, int i) {
        this.etRptAmountEditView.requestFocus();
        EditText editText = this.etRptAmountEditView;
        editText.setSelection(editText.getText().length());
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktGroupSendActivity$oErg1jzDFbWCv7uawS6Sr9sJZVU
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$28$RedpktGroupSendActivity();
            }
        }, 300L);
    }

    public /* synthetic */ void lambda$null$28$RedpktGroupSendActivity() {
        AndroidUtilities.showKeyboard(this.etRptAmountEditView);
    }

    static /* synthetic */ void lambda$null$30(DialogInterface dialogInterface, int i) {
    }

    public /* synthetic */ void lambda$null$32$RedpktGroupSendActivity(DialogInterface dialogInterface, int i) {
        presentFragment(new AboutAppActivity());
    }

    public /* synthetic */ void lambda$null$33$RedpktGroupSendActivity(DialogInterface dialogInterface, int i) {
        this.etRptAmountEditView.setText("");
    }

    public /* synthetic */ void lambda$sendRedpacket$36$RedpktGroupSendActivity(DialogInterface dialog) {
        getConnectionsManager().cancelRequest(this.reqId, true);
    }

    public void performService(final BaseFragment fragment) {
        String userString;
        final int currentAccount = fragment.getCurrentAccount();
        final SharedPreferences preferences = MessagesController.getMainSettings(currentAccount);
        int uid = preferences.getInt("support_id", 0);
        TLRPC.User supportUser = null;
        if (uid != 0 && (supportUser = MessagesController.getInstance(currentAccount).getUser(Integer.valueOf(uid))) == null && (userString = preferences.getString("support_user", null)) != null) {
            try {
                byte[] datacentersBytes = Base64.decode(userString, 0);
                if (datacentersBytes != null) {
                    SerializedData data = new SerializedData(datacentersBytes);
                    supportUser = TLRPC.User.TLdeserialize(data, data.readInt32(false), false);
                    if (supportUser != null && supportUser.id == 333000) {
                        supportUser = null;
                    }
                    data.cleanup();
                }
            } catch (Exception e) {
                FileLog.e(e);
                supportUser = null;
            }
        }
        if (supportUser == null) {
            final XAlertDialog progressDialog = new XAlertDialog(getParentActivity(), 4);
            progressDialog.show();
            TLRPC.TL_help_getSupport req = new TLRPC.TL_help_getSupport();
            ConnectionsManager.getInstance(currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktGroupSendActivity$L6uLZ-QchnTj5KWyzUuxnZjIQo4
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    RedpktGroupSendActivity.lambda$performService$39(preferences, progressDialog, currentAccount, fragment, tLObject, tL_error);
                }
            });
            return;
        }
        MessagesController.getInstance(currentAccount).putUser(supportUser, true);
        Bundle args = new Bundle();
        args.putInt("user_id", supportUser.id);
        fragment.presentFragment(new ChatActivity(args));
    }

    static /* synthetic */ void lambda$performService$39(final SharedPreferences preferences, final XAlertDialog progressDialog, final int currentAccount, final BaseFragment fragment, TLObject response, TLRPC.TL_error error) {
        if (error == null) {
            final TLRPC.TL_help_support res = (TLRPC.TL_help_support) response;
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktGroupSendActivity$8hKJtw0L_Qw7yDc_QukP93Jk-EY
                @Override // java.lang.Runnable
                public final void run() {
                    RedpktGroupSendActivity.lambda$null$37(preferences, res, progressDialog, currentAccount, fragment);
                }
            });
        } else {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktGroupSendActivity$GbokK4KX-855B-QjkwbRpaTaHVA
                @Override // java.lang.Runnable
                public final void run() {
                    RedpktGroupSendActivity.lambda$null$38(progressDialog);
                }
            });
        }
    }

    static /* synthetic */ void lambda$null$37(SharedPreferences preferences, TLRPC.TL_help_support res, XAlertDialog progressDialog, int currentAccount, BaseFragment fragment) {
        SharedPreferences.Editor editor = preferences.edit();
        editor.putInt("support_id", res.user.id);
        SerializedData data = new SerializedData();
        res.user.serializeToStream(data);
        editor.putString("support_user", Base64.encodeToString(data.toByteArray(), 0));
        editor.commit();
        data.cleanup();
        try {
            progressDialog.dismiss();
        } catch (Exception e) {
            FileLog.e(e);
        }
        ArrayList<TLRPC.User> users = new ArrayList<>();
        users.add(res.user);
        MessagesStorage.getInstance(currentAccount).putUsersAndChats(users, null, true, true);
        MessagesController.getInstance(currentAccount).putUser(res.user, false);
        Bundle args = new Bundle();
        args.putInt("user_id", res.user.id);
        fragment.presentFragment(new ChatActivity(args));
    }

    static /* synthetic */ void lambda$null$38(XAlertDialog progressDialog) {
        try {
            progressDialog.dismiss();
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public void setParticipants(TLRPC.ChatFull chatFull) {
        this.chatFull = chatFull;
    }

    private class MyAdapter extends BaseAdapter {
        private MyAdapter() {
        }

        @Override // android.widget.Adapter
        public int getCount() {
            return RedpktGroupSendActivity.this.mNumbers.size();
        }

        @Override // android.widget.Adapter
        public Integer getItem(int position) {
            return (Integer) RedpktGroupSendActivity.this.mNumbers.get(position);
        }

        @Override // android.widget.Adapter
        public long getItemId(int position) {
            return position;
        }

        @Override // android.widget.Adapter
        public View getView(int position, View convertView, ViewGroup parent) {
            ViewHolder holder;
            if (convertView == null) {
                convertView = View.inflate(RedpktGroupSendActivity.this.mContext, R.layout.item_password_number, null);
                holder = RedpktGroupSendActivity.this.new ViewHolder();
                holder.tvNumber = (TextView) convertView.findViewById(R.attr.btn_number);
                holder.ivDelete = (ImageView) convertView.findViewById(R.attr.iv_delete);
                convertView.setTag(holder);
            } else {
                holder = (ViewHolder) convertView.getTag();
            }
            if (position < 9 || position == 10) {
                holder.tvNumber.setText(String.valueOf(RedpktGroupSendActivity.this.mNumbers.get(position)));
                holder.tvNumber.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
            } else if (position == 9) {
                holder.tvNumber.setVisibility(4);
            } else if (position == 11) {
                holder.tvNumber.setVisibility(4);
                holder.ivDelete.setVisibility(0);
            }
            return convertView;
        }
    }

    class ViewHolder {
        ImageView ivDelete;
        TextView tvNumber;

        ViewHolder() {
        }
    }
}
