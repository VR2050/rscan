package im.uwrkaxlmjj.ui.wallet;

import android.content.Context;
import android.text.Editable;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.util.SparseArray;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.ItemTouchHelper;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewpager.widget.PagerAdapter;
import androidx.viewpager.widget.ViewPager;
import com.blankj.utilcode.util.ColorUtils;
import com.king.zxing.util.CodeUtils;
import com.tablayout.SlidingScaleTabLayout;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLApiModel;
import im.uwrkaxlmjj.tgnet.TLJsonResolve;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.tgnet.TLRPCWallet;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.components.AppTextView;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.components.SimpleTextWatcher;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.hui.wallet_public.bean.WalletAccountInfo;
import im.uwrkaxlmjj.ui.hviews.NoScrollViewPager;
import im.uwrkaxlmjj.ui.hviews.swipelist.SlidingItemMenuRecyclerView;
import im.uwrkaxlmjj.ui.load.SpinKitView;
import im.uwrkaxlmjj.ui.wallet.cell.BtnChargeCell;
import im.uwrkaxlmjj.ui.wallet.model.AmountRulesBean;
import im.uwrkaxlmjj.ui.wallet.model.ChargeResBean;
import im.uwrkaxlmjj.ui.wallet.model.Constants;
import im.uwrkaxlmjj.ui.wallet.model.PayChannelBean;
import im.uwrkaxlmjj.ui.wallet.model.PayChannelsResBean;
import im.uwrkaxlmjj.ui.wallet.model.PayTypeListBean;
import im.uwrkaxlmjj.ui.wallet.utils.AnimationUtils;
import im.uwrkaxlmjj.ui.wallet.utils.ExceptionUtils;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class WalletTopUpActivity extends BaseFragment {
    private Adapter adapter;
    private AppTextView btnEmpty;
    private LinearLayout container;
    private LinearLayout emptyLayout;
    private ImageView ivEmpty;
    private SpinKitView loadView;
    private boolean loadingPayChannels;
    private ViewPager.OnPageChangeListener onPageChangeListener;
    private ArrayList<PayChannelBean> payList = new ArrayList<>();
    private SlidingScaleTabLayout tabLayout;
    private TextView tvDesc;
    private TextView tvEmpty;
    private NoScrollViewPager viewPager;

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean canBeginSlide() {
        ArrayList<PayChannelBean> arrayList = this.payList;
        return arrayList == null || arrayList.size() == 0 || this.viewPager.getCurrentItem() == 0;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.fragmentView = LayoutInflater.from(context).inflate(R.layout.activity_wallet_top_up_layout, (ViewGroup) null, false);
        initActionBar();
        initViews();
        showLoading();
        loadPayChannels();
        return this.fragmentView;
    }

    private void initActionBar() {
        this.actionBar.setTitle(LocaleController.getString(R.string.TopUp));
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setCastShadows(false);
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.wallet.WalletTopUpActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    WalletTopUpActivity.this.finishFragment();
                }
            }
        });
    }

    private void initViews() {
        this.emptyLayout = (LinearLayout) this.fragmentView.findViewById(R.attr.emptyLayout);
        this.loadView = (SpinKitView) this.fragmentView.findViewById(R.attr.loadView);
        this.ivEmpty = (ImageView) this.fragmentView.findViewById(R.attr.ivEmpty);
        this.tvEmpty = (TextView) this.fragmentView.findViewById(R.attr.tvEmpty);
        this.tvDesc = (TextView) this.fragmentView.findViewById(R.attr.tvDesc);
        this.btnEmpty = (AppTextView) this.fragmentView.findViewById(R.attr.btnEmpty);
        this.container = (LinearLayout) this.fragmentView.findViewById(R.attr.container);
        this.tabLayout = (SlidingScaleTabLayout) this.fragmentView.findViewById(R.attr.tabLayout);
        this.viewPager = (NoScrollViewPager) this.fragmentView.findViewById(R.attr.viewPager);
        this.tabLayout.setTextUnSelectColor(ColorUtils.getColor(R.color.tab_normal_text));
        this.tabLayout.setTextSelectColor(ColorUtils.getColor(R.color.tab_active_text));
        this.tabLayout.setIndicatorColor(ColorUtils.getColor(R.color.tab_indicator));
        this.viewPager.setEnScroll(true);
        this.viewPager.setOffscreenPageLimit(1);
        NoScrollViewPager noScrollViewPager = this.viewPager;
        ViewPager.OnPageChangeListener onPageChangeListener = new ViewPager.OnPageChangeListener() { // from class: im.uwrkaxlmjj.ui.wallet.WalletTopUpActivity.2
            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageScrolled(int position, float positionOffset, int positionOffsetPixels) {
            }

            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageSelected(int position) {
                WalletTopUpActivity.this.notifyInnerRvAdapter(position);
            }

            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageScrollStateChanged(int state) {
            }
        };
        this.onPageChangeListener = onPageChangeListener;
        noScrollViewPager.addOnPageChangeListener(onPageChangeListener);
        Adapter adapter = new Adapter();
        this.adapter = adapter;
        this.viewPager.setAdapter(adapter);
        this.tabLayout.setViewPager(this.viewPager);
    }

    private void showLoading() {
        this.container.setVisibility(8);
        this.btnEmpty.setVisibility(8);
        this.tvDesc.setVisibility(8);
        this.emptyLayout.setVisibility(0);
        this.loadView.setVisibility(0);
        this.tvEmpty.setTextColor(ColorUtils.getColor(R.color.text_descriptive_color));
        this.tvEmpty.setText(LocaleController.getString(R.string.NowLoading));
        this.ivEmpty.setVisibility(8);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showError() {
        this.emptyLayout.setVisibility(0);
        this.container.setVisibility(8);
        this.tvDesc.setVisibility(8);
        this.loadView.setVisibility(8);
        AnimationUtils.executeAlphaScaleDisplayAnimation(this.emptyLayout);
        this.ivEmpty.setVisibility(0);
        this.ivEmpty.setImageResource(R.id.ic_data_ex);
        this.btnEmpty.setVisibility(0);
        this.tvEmpty.setText(LocaleController.getString(R.string.SystemIsBusyAndTryAgainLater));
        this.tvEmpty.setTextColor(ColorUtils.getColor(R.color.text_primary_color));
        this.tvDesc.setText(LocaleController.getString(R.string.ClickTheButtonToTryAgain));
        this.btnEmpty.setText(LocaleController.getString(R.string.Refresh));
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showContainer() {
        this.emptyLayout.setVisibility(8);
        this.container.setVisibility(0);
        AnimationUtils.executeAlphaScaleDisplayAnimation(this.container);
    }

    private void loadPayChannels() {
        if (this.loadingPayChannels) {
            return;
        }
        this.loadingPayChannels = true;
        TLRPCWallet.Builder builder = new TLRPCWallet.Builder();
        builder.setBusinessKey(Constants.KEY_PAY_CHANNELS);
        builder.addParam("belongType", "topup");
        builder.addParam("company", "Sbcc");
        TLRPCWallet.TL_paymentTrans req = builder.build();
        getConnectionsManager().bindRequestToGuid(getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletTopUpActivity$6rKagAE2eun9wzdL7zoMew4QGyY
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$loadPayChannels$0$WalletTopUpActivity(tLObject, tL_error);
            }
        }), this.classGuid);
    }

    public /* synthetic */ void lambda$loadPayChannels$0$WalletTopUpActivity(final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.wallet.WalletTopUpActivity.3
            @Override // java.lang.Runnable
            public void run() {
                WalletTopUpActivity.this.loadingPayChannels = false;
                if (error != null) {
                    WalletTopUpActivity.this.showError();
                    ExceptionUtils.handlePayChannelException(error.text);
                }
                TLObject tLObject = response;
                if (tLObject instanceof TLRPCWallet.TL_paymentTransResult) {
                    TLRPCWallet.TL_paymentTransResult result = (TLRPCWallet.TL_paymentTransResult) tLObject;
                    TLApiModel parse = TLJsonResolve.parse(result.data, (Class<?>) PayChannelsResBean.class);
                    if (parse.isSuccess()) {
                        WalletTopUpActivity.this.showContainer();
                        List modelList = parse.modelList;
                        if (modelList != null || !modelList.isEmpty()) {
                            WalletTopUpActivity.this.parsePayChannel(modelList);
                            return;
                        }
                        return;
                    }
                    WalletTopUpActivity.this.showError();
                    ExceptionUtils.handlePayChannelException(parse.message);
                }
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void parsePayChannel(List<PayChannelsResBean> modelList) {
        ArrayList<PayTypeListBean> payTypeList;
        if (modelList == null || modelList.isEmpty()) {
            return;
        }
        for (int i = 0; i < modelList.size(); i++) {
            PayChannelsResBean payChannelsResBean = modelList.get(i);
            if (payChannelsResBean != null && payChannelsResBean.getPayTypeList() != null && !payChannelsResBean.getPayTypeList().isEmpty() && (payTypeList = payChannelsResBean.getPayTypeList()) != null && !payTypeList.isEmpty()) {
                for (int j = 0; j < payTypeList.size(); j++) {
                    PayChannelBean bean = new PayChannelBean();
                    bean.setChannelCode(payChannelsResBean.getChannelCode());
                    bean.setPayType(payTypeList.get(j));
                    this.payList.add(bean);
                }
            }
        }
        notifyAdapter();
    }

    private void notifyAdapter() {
        Adapter adapter = this.adapter;
        if (adapter != null) {
            adapter.notifyDataSetChanged();
            this.viewPager.setOffscreenPageLimit(this.adapter.getCount());
        }
        SlidingScaleTabLayout slidingScaleTabLayout = this.tabLayout;
        if (slidingScaleTabLayout != null) {
            slidingScaleTabLayout.notifyDataSetChanged();
        }
        notifyInnerRvAdapter(this.viewPager.getCurrentItem());
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void notifyInnerRvAdapter(final int position) {
        ArrayList<PayChannelBean> arrayList;
        if (this.adapter != null && (arrayList = this.payList) != null && position < arrayList.size()) {
            final PayChannelBean itemData = this.payList.get(position);
            this.fragmentView.postDelayed(new Runnable() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletTopUpActivity$jsj4LbwZEasaWQe-w6DwM764jtQ
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$notifyInnerRvAdapter$1$WalletTopUpActivity(position, itemData);
                }
            }, 200L);
        }
    }

    public /* synthetic */ void lambda$notifyInnerRvAdapter$1$WalletTopUpActivity(int position, PayChannelBean itemData) {
        InnerPage innerPage = this.adapter.getItem(position);
        if (innerPage != null) {
            innerPage.setItemData(itemData);
        }
        this.adapter.setData(itemData);
    }

    public class InnerPage extends FrameLayout {
        private NumberAdapter adapter;
        private AppTextView btn;
        private EditText etMoney;
        private TextWatcher etWatcher;
        private PayChannelBean itemData;
        private RecyclerListView listView;

        public InnerPage(Context context) {
            super(context);
            this.etWatcher = new TextWatcher() { // from class: im.uwrkaxlmjj.ui.wallet.WalletTopUpActivity.InnerPage.4
                @Override // android.text.TextWatcher
                public void beforeTextChanged(CharSequence s, int start, int count, int after) {
                }

                @Override // android.text.TextWatcher
                public void onTextChanged(CharSequence s, int start, int before, int count) {
                }

                @Override // android.text.TextWatcher
                public void afterTextChanged(Editable s) {
                    InnerPage.this.updateBtnEnable();
                }
            };
            inflate(context, R.layout.wallet_recharge_inner_page, this);
            this.etMoney = (EditText) findViewById(R.attr.etMoney);
            this.listView = (RecyclerListView) findViewById(R.attr.listView);
            this.btn = (AppTextView) findViewById(R.attr.btn);
            this.listView.setLayoutManager(new GridLayoutManager(context, 3));
            RecyclerListView recyclerListView = this.listView;
            NumberAdapter numberAdapter = WalletTopUpActivity.this.new NumberAdapter(context);
            this.adapter = numberAdapter;
            recyclerListView.setAdapter(numberAdapter);
            this.listView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.wallet.WalletTopUpActivity.InnerPage.1
                @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
                public void onItemClick(View view, int position) {
                    Integer integer = InnerPage.this.adapter.getValue(position);
                    InnerPage.this.etMoney.setText(String.valueOf(integer));
                    InnerPage.this.etMoney.setSelection(InnerPage.this.etMoney.getText().toString().length());
                    InnerPage.this.clearChecked();
                    if (view instanceof BtnChargeCell) {
                        BtnChargeCell cell = (BtnChargeCell) view;
                        cell.setChecked(true);
                    }
                }
            });
            this.etMoney.addTextChangedListener(new SimpleTextWatcher() { // from class: im.uwrkaxlmjj.ui.wallet.WalletTopUpActivity.InnerPage.2
                @Override // im.uwrkaxlmjj.ui.components.SimpleTextWatcher, android.text.TextWatcher
                public void onTextChanged(CharSequence s, int start, int before, int count) {
                    InnerPage.this.setBtnEnable((TextUtils.isEmpty(s) || InnerPage.this.itemData == null) ? false : true);
                }
            });
            this.btn.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletTopUpActivity$InnerPage$J-S8itcdtbDS9JtoI-c_NzcmZfs
                @Override // android.view.View.OnClickListener
                public final void onClick(View view) {
                    this.f$0.lambda$new$0$WalletTopUpActivity$InnerPage(view);
                }
            });
            setBtnEnable(false);
            updateViewData();
        }

        public /* synthetic */ void lambda$new$0$WalletTopUpActivity$InnerPage(View v) {
            PayTypeListBean payType;
            if (AndroidUtilities.isKeyboardShowed(this.etMoney)) {
                AndroidUtilities.hideKeyboard(this.etMoney);
            }
            PayChannelBean payChannelBean = this.itemData;
            if (payChannelBean == null || (payType = payChannelBean.getPayType()) == null) {
                return;
            }
            String amount = this.etMoney.getText().toString().trim();
            String bigAmount = new BigDecimal(amount).multiply(new BigDecimal("100")).toString();
            AmountRulesBean amountRules = payType.getAmountRules();
            if (amountRules != null && !TextUtils.isEmpty(bigAmount)) {
                String maxAmount = amountRules.getMaxAmount();
                String minAmount = amountRules.getMinAmount();
                if (!"0".equals(maxAmount) && !TextUtils.isEmpty(maxAmount) && new BigDecimal(bigAmount).compareTo(new BigDecimal(maxAmount).multiply(new BigDecimal("100"))) > 0) {
                    ToastUtils.show((CharSequence) ("最大值" + maxAmount));
                    return;
                }
                if (!"0".equals(minAmount) && !TextUtils.isEmpty(minAmount) && new BigDecimal(bigAmount).compareTo(new BigDecimal(minAmount).multiply(new BigDecimal("100"))) < 0) {
                    ToastUtils.show((CharSequence) ("最小值" + minAmount));
                    return;
                }
            }
            doCharge(bigAmount);
        }

        private void doCharge(String amount) {
            TLRPCWallet.Builder builder = new TLRPCWallet.Builder();
            builder.setBusinessKey(Constants.KEY_PAY_CHARGE);
            builder.addParam("amount", amount);
            builder.addParam("userId", Integer.valueOf(WalletTopUpActivity.this.getUserConfig().clientUserId));
            builder.addParam("channelCode", this.itemData.getChannelCode());
            builder.addParam("payType", this.itemData.getPayType().getPayType());
            TLRPCWallet.TL_paymentTrans req = builder.build();
            WalletTopUpActivity.this.getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletTopUpActivity$InnerPage$AFhjVSYon-FWpZJNHKUOhpbhcRc
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$doCharge$1$WalletTopUpActivity$InnerPage(tLObject, tL_error);
                }
            });
        }

        public /* synthetic */ void lambda$doCharge$1$WalletTopUpActivity$InnerPage(TLObject response, TLRPC.TL_error error) {
            if (error != null) {
                ExceptionUtils.handlePayChannelException(error.text);
                return;
            }
            if (response instanceof TLRPCWallet.TL_paymentTransResult) {
                TLRPCWallet.TL_paymentTransResult result = (TLRPCWallet.TL_paymentTransResult) response;
                TLApiModel<ChargeResBean> parse = TLJsonResolve.parse(result.data, (Class<?>) ChargeResBean.class);
                if (parse.isSuccess()) {
                    final ChargeResBean model = parse.model;
                    AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.wallet.WalletTopUpActivity.InnerPage.3
                        @Override // java.lang.Runnable
                        public void run() {
                            WalletTopUpActivity.this.presentFragment(new WalletRechargeH5Activity(1, model.getAction()), true);
                        }
                    });
                } else if ("-1".equals(parse.code)) {
                    ToastUtils.show((CharSequence) LocaleController.getString(R.string.RechargeFailed));
                } else {
                    ExceptionUtils.handlePayChannelException(parse.message);
                }
            }
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setBtnEnable(boolean enable) {
            this.btn.setEnabled(enable);
            if (enable) {
                this.btn.setTextColor(ColorUtils.getColor(R.color.text_white_color));
                this.btn.setBackgroundResource(R.drawable.btn_primary_selector);
            } else {
                this.btn.setTextColor(ColorUtils.getColor(R.color.text_secondary_color));
                this.btn.setBackgroundResource(R.drawable.shape_rect_round_white);
            }
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clearChecked() {
            int childCount = this.listView.getChildCount();
            for (int i = 0; i < childCount; i++) {
                View childAt = this.listView.getChildAt(i);
                if (childAt instanceof BtnChargeCell) {
                    BtnChargeCell cell = (BtnChargeCell) childAt;
                    cell.setChecked(false);
                }
            }
        }

        private void updateViewData() {
            WalletAccountInfo accountInfo = WalletTopUpActivity.this.getWalletController().getAccountInfo();
            if (accountInfo == null) {
                return;
            }
            updateBtnEnable();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void updateBtnEnable() {
            AppTextView appTextView = this.btn;
            if (appTextView == null || this.etMoney == null) {
                return;
            }
            appTextView.setEnabled(false);
        }

        void setItemData(PayChannelBean itemData) {
            this.itemData = itemData;
            if (itemData != null && itemData.getPayType() != null) {
                PayTypeListBean payType = itemData.getPayType();
                if (payType.getAmountRules() != null) {
                    if (payType.getAmountRules().getSelf() == 1) {
                        this.etMoney.setEnabled(true);
                        this.etMoney.setHint(LocaleController.getString(R.string.PleaseInputRechargeMoneyAmount));
                    } else {
                        this.etMoney.setEnabled(false);
                        this.etMoney.setHint(LocaleController.getString(R.string.PleaseSelectRechargeMoneyAmount));
                    }
                    String amount = payType.getAmountRules().getAmount();
                    ArrayList<Integer> integers = new ArrayList<>();
                    if (!TextUtils.isEmpty(amount) && !"0".equals(amount)) {
                        String[] split = amount.split(",");
                        if (split != null && split.length > 0) {
                            for (String str : split) {
                                integers.add(Integer.valueOf(Integer.parseInt(str)));
                            }
                        }
                    } else {
                        integers.add(50);
                        integers.add(100);
                        integers.add(Integer.valueOf(ItemTouchHelper.Callback.DEFAULT_DRAG_ANIMATION_DURATION));
                        integers.add(Integer.valueOf(SlidingItemMenuRecyclerView.DEFAULT_ITEM_SCROLL_DURATION));
                        integers.add(Integer.valueOf(CodeUtils.DEFAULT_REQ_HEIGHT));
                        integers.add(1000);
                    }
                    NumberAdapter numberAdapter = this.adapter;
                    if (numberAdapter != null) {
                        numberAdapter.setNumberList(integers);
                        this.adapter.notifyDataSetChanged();
                    }
                }
            }
        }

        String getInputText() {
            EditText editText = this.etMoney;
            return (editText == null || editText.getText() == null) ? "" : this.etMoney.getText().toString().trim();
        }

        void onDestroy() {
            TextWatcher textWatcher;
            removeAllViews();
            EditText editText = this.etMoney;
            if (editText != null && (textWatcher = this.etWatcher) != null) {
                editText.removeTextChangedListener(textWatcher);
                this.etWatcher = null;
            }
            this.btn = null;
            this.etMoney = null;
            this.adapter = null;
        }
    }

    private class NumberAdapter extends RecyclerListView.SelectionAdapter {
        private Context mContext;
        private ArrayList<Integer> numberList = new ArrayList<>();

        public NumberAdapter(Context mContext) {
            this.mContext = mContext;
        }

        public void setNumberList(ArrayList<Integer> numberList) {
            this.numberList = numberList;
        }

        public Integer getValue(int position) {
            return this.numberList.get(position);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view = new BtnChargeCell(this.mContext);
            return new RecyclerListView.Holder(view);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            BtnChargeCell cell = (BtnChargeCell) holder.itemView;
            cell.setText(this.numberList.get(position) + LocaleController.getString(R.string.UnitMoneyYuan));
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            return this.numberList.size();
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            return false;
        }
    }

    private class Adapter extends PagerAdapter {
        private final SparseArray<InnerPage> viewCaches = new SparseArray<>();

        public Adapter() {
        }

        InnerPage getItem(int position) {
            return this.viewCaches.get(position);
        }

        void setData(PayChannelBean itemData) {
            if (WalletTopUpActivity.this.viewPager == null || itemData == null) {
            }
        }

        @Override // androidx.viewpager.widget.PagerAdapter
        public CharSequence getPageTitle(int position) {
            return (WalletTopUpActivity.this.payList == null || position >= WalletTopUpActivity.this.payList.size()) ? "" : ((PayChannelBean) WalletTopUpActivity.this.payList.get(position)).getPayType().getName();
        }

        @Override // androidx.viewpager.widget.PagerAdapter
        public int getCount() {
            if (WalletTopUpActivity.this.payList != null) {
                return WalletTopUpActivity.this.payList.size();
            }
            return 0;
        }

        @Override // androidx.viewpager.widget.PagerAdapter
        public Object instantiateItem(ViewGroup container, int position) {
            InnerPage innerCell = getItem(position);
            if (innerCell == null) {
                innerCell = WalletTopUpActivity.this.new InnerPage(container.getContext());
                this.viewCaches.put(position, innerCell);
            }
            if (innerCell.getParent() != null) {
                ViewGroup parent = (ViewGroup) innerCell.getParent();
                parent.removeView(innerCell);
            }
            AndroidUtilities.showKeyboard(innerCell.etMoney);
            container.addView(innerCell, 0);
            return innerCell;
        }

        @Override // androidx.viewpager.widget.PagerAdapter
        public boolean isViewFromObject(View view, Object object) {
            return view == object;
        }

        @Override // androidx.viewpager.widget.PagerAdapter
        public void destroyItem(ViewGroup container, int position, Object object) {
            container.removeView((View) object);
        }

        @Override // androidx.viewpager.widget.PagerAdapter
        public void notifyDataSetChanged() {
            super.notifyDataSetChanged();
        }

        void onDestroy() {
            for (int i = 0; i < this.viewCaches.size(); i++) {
                InnerPage page = this.viewCaches.get(i);
                if (page != null) {
                    page.onDestroy();
                }
            }
            this.viewCaches.clear();
        }
    }
}
