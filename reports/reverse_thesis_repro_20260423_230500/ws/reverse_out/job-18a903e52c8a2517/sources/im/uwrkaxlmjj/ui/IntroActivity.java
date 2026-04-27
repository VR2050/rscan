package im.uwrkaxlmjj.ui;

import android.animation.ObjectAnimator;
import android.animation.StateListAnimator;
import android.app.Activity;
import android.content.Intent;
import android.content.SharedPreferences;
import android.database.DataSetObserver;
import android.graphics.Color;
import android.graphics.Shader;
import android.graphics.drawable.BitmapDrawable;
import android.os.Build;
import android.os.Bundle;
import android.os.Parcelable;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.ScrollView;
import android.widget.TextView;
import androidx.viewpager.widget.PagerAdapter;
import androidx.viewpager.widget.ViewPager;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.BuildVars;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.BottomPagesView;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import mpEIGo.juqQQs.esbSDO.R;
import org.webrtc.mozi.JavaScreenCapturer;

/* JADX INFO: loaded from: classes5.dex */
public class IntroActivity extends Activity implements NotificationCenter.NotificationCenterDelegate {
    private BottomPagesView bottomPages;
    private long currentDate;
    private int currentViewPagerPage;
    private boolean destroyed;
    private boolean dragging;
    private int[] images;
    private boolean justEndDragging;
    private LocaleController.LocaleInfo localeInfo;
    private String[] messages;
    private int startDragX;
    private TextView startMessagingButton;
    private TextView textView;
    private String[] titles;
    private ViewPager viewPager;
    private int currentAccount = UserConfig.selectedAccount;
    private int lastPage = 0;
    private boolean justCreated = false;
    private boolean startPressed = false;

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r11v19, types: [android.view.View, android.widget.FrameLayout] */
    /* JADX WARN: Type inference failed for: r17v0 */
    /* JADX WARN: Type inference failed for: r17v1 */
    /* JADX WARN: Type inference failed for: r17v2 */
    /* JADX WARN: Type inference failed for: r25v0, types: [android.app.Activity, android.content.Context, im.uwrkaxlmjj.ui.IntroActivity, java.lang.Object] */
    /* JADX WARN: Type inference failed for: r3v16, types: [android.view.View, android.widget.FrameLayout] */
    /* JADX WARN: Type inference failed for: r4v4, types: [android.widget.ScrollView] */
    /* JADX WARN: Type inference failed for: r8v10, types: [android.view.View] */
    /* JADX WARN: Type inference failed for: r8v7, types: [android.view.View] */
    @Override // android.app.Activity
    protected void onCreate(Bundle savedInstanceState) {
        ?? r17;
        jumpIntro();
        setTheme(2131755390);
        super.onCreate(savedInstanceState);
        requestWindowFeature(1);
        SharedPreferences preferences = MessagesController.getGlobalMainSettings();
        preferences.edit().putLong("intro_crashed_time", System.currentTimeMillis()).commit();
        this.titles = new String[]{LocaleController.getString("Page1Title", R.string.Page1Title), LocaleController.getString("Page2Title", R.string.Page2Title), LocaleController.getString("Page3Title", R.string.Page3Title), LocaleController.getString("Page4Title", R.string.Page4Title)};
        this.messages = new String[]{LocaleController.getString("Page1Message", R.string.Page1Message), LocaleController.getString("Page2Message", R.string.Page2Message), LocaleController.getString("Page3Message", R.string.Page3Message), LocaleController.getString("Page4Message", R.string.Page4Message)};
        this.images = new int[]{R.id.img_intro_secure, R.id.img_intro_secure2, R.id.img_intro_group, R.id.img_intro_private};
        ?? scrollView = new ScrollView(this);
        scrollView.setFillViewport(true);
        FrameLayout frameLayout = new FrameLayout(this);
        frameLayout.setBackgroundColor(-1);
        scrollView.addView(frameLayout, LayoutHelper.createScroll(-1, -2, 51));
        FrameLayout frameLayout2 = new FrameLayout(this);
        frameLayout.addView(frameLayout2, LayoutHelper.createFrame(-1.0f, -2.0f, 51, 0.0f, 78.0f, 0.0f, 0.0f));
        final ImageView introImg = new ImageView(this);
        introImg.setScaleType(ImageView.ScaleType.CENTER_INSIDE);
        frameLayout2.addView(introImg, LayoutHelper.createFrame(JavaScreenCapturer.DEGREE_270, JavaScreenCapturer.DEGREE_270, 17));
        ViewPager viewPager = new ViewPager(this);
        this.viewPager = viewPager;
        viewPager.setAdapter(new IntroAdapter());
        this.viewPager.setPageMargin(0);
        this.viewPager.setOffscreenPageLimit(1);
        frameLayout.addView(this.viewPager, LayoutHelper.createFrame(-1, -1.0f));
        this.viewPager.addOnPageChangeListener(new ViewPager.OnPageChangeListener() { // from class: im.uwrkaxlmjj.ui.IntroActivity.1
            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageScrolled(int position, float positionOffset, int positionOffsetPixels) {
                IntroActivity.this.bottomPages.setPageOffset(position, positionOffset);
                float width = IntroActivity.this.viewPager.getMeasuredWidth();
                if (width != 0.0f) {
                    float offset = (((position * width) + positionOffsetPixels) - (IntroActivity.this.currentViewPagerPage * width)) / width;
                    introImg.setAlpha(1.0f - Math.abs(offset));
                }
            }

            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageSelected(int i) {
                IntroActivity.this.currentViewPagerPage = i;
                introImg.setImageResource(IntroActivity.this.images[IntroActivity.this.currentViewPagerPage]);
                IntroActivity.this.startMessagingButton.setVisibility(i == 3 ? 0 : 8);
            }

            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageScrollStateChanged(int i) {
                if (i == 1) {
                    IntroActivity.this.dragging = true;
                    IntroActivity introActivity = IntroActivity.this;
                    introActivity.startDragX = introActivity.viewPager.getCurrentItem() * IntroActivity.this.viewPager.getMeasuredWidth();
                } else if (i == 0 || i == 2) {
                    if (IntroActivity.this.dragging) {
                        IntroActivity.this.justEndDragging = true;
                        IntroActivity.this.dragging = false;
                    }
                    if (IntroActivity.this.lastPage != IntroActivity.this.viewPager.getCurrentItem()) {
                        IntroActivity introActivity2 = IntroActivity.this;
                        introActivity2.lastPage = introActivity2.viewPager.getCurrentItem();
                    }
                }
            }
        });
        introImg.setImageResource(this.images[this.currentViewPagerPage]);
        TextView textView = new TextView(this);
        this.startMessagingButton = textView;
        textView.setText(LocaleController.getString("StartMessaging", R.string.StartMessaging).toUpperCase());
        this.startMessagingButton.setGravity(17);
        this.startMessagingButton.setTextColor(-1);
        this.startMessagingButton.setTextSize(1, 16.0f);
        this.startMessagingButton.setVisibility(8);
        this.startMessagingButton.setBackground(Theme.createSimpleSelectorRoundRectDrawable(AndroidUtilities.dp(24.0f), Color.parseColor("#FF268CFF"), Color.parseColor("#FF1E69BD")));
        if (Build.VERSION.SDK_INT < 21) {
            r17 = scrollView;
        } else {
            StateListAnimator animator = new StateListAnimator();
            r17 = scrollView;
            animator.addState(new int[]{android.R.attr.state_pressed}, ObjectAnimator.ofFloat(this.startMessagingButton, "translationZ", AndroidUtilities.dp(2.0f), AndroidUtilities.dp(4.0f)).setDuration(200L));
            animator.addState(new int[0], ObjectAnimator.ofFloat(this.startMessagingButton, "translationZ", AndroidUtilities.dp(4.0f), AndroidUtilities.dp(2.0f)).setDuration(200L));
            this.startMessagingButton.setStateListAnimator(animator);
        }
        this.startMessagingButton.setPadding(AndroidUtilities.dp(20.0f), AndroidUtilities.dp(10.0f), AndroidUtilities.dp(20.0f), AndroidUtilities.dp(10.0f));
        frameLayout.addView(this.startMessagingButton, LayoutHelper.createFrame(-2.0f, -2.0f, 81, 10.0f, 0.0f, 10.0f, 76.0f));
        this.startMessagingButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$IntroActivity$P_APexNzJSRuDj5LxqaW2XHDE8g
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$onCreate$0$IntroActivity(view);
            }
        });
        if (BuildVars.DEBUG_VERSION) {
            this.startMessagingButton.setOnLongClickListener(new View.OnLongClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$IntroActivity$cxOyJt_D4eJASOjuFR12ervb7fM
                @Override // android.view.View.OnLongClickListener
                public final boolean onLongClick(View view) {
                    return this.f$0.lambda$onCreate$1$IntroActivity(view);
                }
            });
        }
        BottomPagesView bottomPagesView = new BottomPagesView(this, this.viewPager, 4);
        this.bottomPages = bottomPagesView;
        frameLayout.addView(bottomPagesView, LayoutHelper.createFrame(44.0f, 5.0f, 81, 0.0f, 0.0f, 0.0f, 50.0f));
        TextView textView2 = new TextView(this);
        this.textView = textView2;
        textView2.setTextColor(-15494190);
        this.textView.setGravity(17);
        this.textView.setTextSize(1, 16.0f);
        frameLayout.addView(this.textView, LayoutHelper.createFrame(-2.0f, 30.0f, 81, 0.0f, 0.0f, 0.0f, 20.0f));
        this.textView.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$IntroActivity$F2yai2HnZNAZnXcMmJgH3CYEtcw
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$onCreate$2$IntroActivity(view);
            }
        });
        if (AndroidUtilities.isTablet()) {
            ?? frameLayout3 = new FrameLayout(this);
            setContentView(frameLayout3);
            View imageView = new ImageView(this);
            BitmapDrawable drawable = (BitmapDrawable) getResources().getDrawable(R.drawable.catstile);
            drawable.setTileModeXY(Shader.TileMode.REPEAT, Shader.TileMode.REPEAT);
            imageView.setBackgroundDrawable(drawable);
            frameLayout3.addView(imageView, LayoutHelper.createFrame(-1, -1.0f));
            ?? frameLayout4 = new FrameLayout(this);
            frameLayout4.setBackgroundResource(R.drawable.btnshadow);
            frameLayout4.addView(r17, LayoutHelper.createFrame(-1, -1.0f));
            frameLayout3.addView(frameLayout4, LayoutHelper.createFrame(498, 528, 17));
        } else {
            setRequestedOrientation(1);
            setContentView(r17);
        }
        LocaleController.getInstance().loadRemoteLanguages(this.currentAccount);
        this.justCreated = true;
        NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.suggestedLangpack);
        AndroidUtilities.handleProxyIntent(this, getIntent());
    }

    public /* synthetic */ void lambda$onCreate$0$IntroActivity(View view) {
        if (this.startPressed) {
            return;
        }
        setNotFirstLaunch();
        this.startPressed = true;
        Intent intent2 = new Intent(this, (Class<?>) LaunchActivity.class);
        intent2.putExtra("fromIntro", true);
        startActivity(intent2);
        this.destroyed = true;
        finish();
    }

    public /* synthetic */ boolean lambda$onCreate$1$IntroActivity(View v) {
        ConnectionsManager.getInstance(this.currentAccount).switchBackend();
        return true;
    }

    public /* synthetic */ void lambda$onCreate$2$IntroActivity(View v) {
        if (this.startPressed || this.localeInfo == null) {
            return;
        }
        LocaleController.getInstance().applyLanguage(this.localeInfo, true, false, this.currentAccount);
        this.startPressed = true;
        Intent intent2 = new Intent(this, (Class<?>) LaunchActivity.class);
        intent2.putExtra("fromIntro", true);
        startActivity(intent2);
        this.destroyed = true;
        finish();
    }

    private void jumpIntro() {
        SharedPreferences sp = MessagesController.getGlobalMainSettings();
        if (!sp.getBoolean("isFirstLaunch", true)) {
            Intent intent = new Intent(this, (Class<?>) LaunchActivity.class);
            intent.putExtra("fromIntro", true);
            startActivity(intent);
            this.destroyed = true;
            finish();
        }
    }

    private void setNotFirstLaunch() {
        SharedPreferences sp = MessagesController.getGlobalMainSettings();
        if (sp.getBoolean("isFirstLaunch", true)) {
            SharedPreferences.Editor editor = sp.edit();
            editor.putBoolean("isFirstLaunch", false);
            editor.commit();
        }
    }

    @Override // android.app.Activity
    protected void onResume() {
        super.onResume();
        if (this.justCreated) {
            if (LocaleController.isRTL) {
                this.viewPager.setCurrentItem(6);
                this.lastPage = 6;
            } else {
                this.viewPager.setCurrentItem(0);
                this.lastPage = 0;
            }
            this.justCreated = false;
        }
        ConnectionsManager.getInstance(this.currentAccount).setAppPaused(false, false);
    }

    @Override // android.app.Activity
    protected void onPause() {
        super.onPause();
        ConnectionsManager.getInstance(this.currentAccount).setAppPaused(true, false);
    }

    @Override // android.app.Activity
    protected void onDestroy() {
        super.onDestroy();
        this.destroyed = true;
        NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.suggestedLangpack);
        SharedPreferences preferences = MessagesController.getGlobalMainSettings();
        preferences.edit().putLong("intro_crashed_time", 0L).commit();
    }

    private void checkContinueText() {
        LocaleController.LocaleInfo englishInfo = null;
        LocaleController.LocaleInfo systemInfo = null;
        LocaleController.LocaleInfo currentLocaleInfo = LocaleController.getInstance().getCurrentLocaleInfo();
        final String systemLang = MessagesController.getInstance(this.currentAccount).suggestedLangCode;
        String arg = systemLang.contains("-") ? systemLang.split("-")[0] : systemLang;
        String alias = LocaleController.getLocaleAlias(arg);
        for (int a = 0; a < LocaleController.getInstance().languages.size(); a++) {
            LocaleController.LocaleInfo info = LocaleController.getInstance().languages.get(a);
            if (info.shortName.equals("en")) {
                englishInfo = info;
            }
            if (info.shortName.replace("_", "-").equals(systemLang) || info.shortName.equals(arg) || info.shortName.equals(alias)) {
                systemInfo = info;
            }
            if (englishInfo != null && systemInfo != null) {
                break;
            }
        }
        if (englishInfo == null || systemInfo == null || englishInfo == systemInfo) {
            return;
        }
        TLRPC.TL_langpack_getStrings req = new TLRPC.TL_langpack_getStrings();
        if (systemInfo != currentLocaleInfo) {
            req.lang_code = systemInfo.getLangCode();
            this.localeInfo = systemInfo;
        } else {
            req.lang_code = englishInfo.getLangCode();
            this.localeInfo = englishInfo;
        }
        req.keys.add("ContinueOnThisLanguage");
        ConnectionsManager.getInstance(this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$IntroActivity$IDeOUkc40UVrWKN8tiCohkICCnM
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$checkContinueText$4$IntroActivity(systemLang, tLObject, tL_error);
            }
        }, 8);
    }

    public /* synthetic */ void lambda$checkContinueText$4$IntroActivity(final String systemLang, TLObject response, TLRPC.TL_error error) {
        if (response != null) {
            TLRPC.Vector vector = (TLRPC.Vector) response;
            if (vector.objects.isEmpty()) {
                return;
            }
            final TLRPC.LangPackString string = (TLRPC.LangPackString) vector.objects.get(0);
            if (string instanceof TLRPC.TL_langPackString) {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$IntroActivity$sV8QGqqUgAAHlsKk_oUz7YMYojo
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$3$IntroActivity(string, systemLang);
                    }
                });
            }
        }
    }

    public /* synthetic */ void lambda$null$3$IntroActivity(TLRPC.LangPackString string, String systemLang) {
        if (!this.destroyed) {
            this.textView.setText(string.value);
            SharedPreferences preferences = MessagesController.getGlobalMainSettings();
            preferences.edit().putString("language_showed2", systemLang.toLowerCase()).commit();
        }
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        int i = NotificationCenter.suggestedLangpack;
    }

    private class IntroAdapter extends PagerAdapter {
        private IntroAdapter() {
        }

        @Override // androidx.viewpager.widget.PagerAdapter
        public int getCount() {
            return IntroActivity.this.titles.length;
        }

        @Override // androidx.viewpager.widget.PagerAdapter
        public Object instantiateItem(ViewGroup viewGroup, int position) {
            FrameLayout frameLayout = new FrameLayout(viewGroup.getContext());
            TextView headerTextView = new TextView(viewGroup.getContext());
            headerTextView.setTextColor(-14606047);
            headerTextView.setTextSize(1, 26.0f);
            headerTextView.setGravity(17);
            frameLayout.addView(headerTextView, LayoutHelper.createFrame(-1.0f, -2.0f, 51, 18.0f, 378.0f, 18.0f, 0.0f));
            TextView messageTextView = new TextView(viewGroup.getContext());
            messageTextView.setTextColor(-8355712);
            messageTextView.setTextSize(1, 15.0f);
            messageTextView.setGravity(17);
            frameLayout.addView(messageTextView, LayoutHelper.createFrame(-1.0f, -2.0f, 51, 16.0f, 420.0f, 16.0f, 0.0f));
            viewGroup.addView(frameLayout, 0);
            headerTextView.setText(IntroActivity.this.titles[position]);
            messageTextView.setText(AndroidUtilities.replaceTags(IntroActivity.this.messages[position]));
            return frameLayout;
        }

        @Override // androidx.viewpager.widget.PagerAdapter
        public void destroyItem(ViewGroup container, int position, Object object) {
            container.removeView((View) object);
        }

        @Override // androidx.viewpager.widget.PagerAdapter
        public void setPrimaryItem(ViewGroup container, int position, Object object) {
            super.setPrimaryItem(container, position, object);
            IntroActivity.this.bottomPages.setCurrentPage(position);
            IntroActivity.this.currentViewPagerPage = position;
        }

        @Override // androidx.viewpager.widget.PagerAdapter
        public boolean isViewFromObject(View view, Object object) {
            return view.equals(object);
        }

        @Override // androidx.viewpager.widget.PagerAdapter
        public void restoreState(Parcelable arg0, ClassLoader arg1) {
        }

        @Override // androidx.viewpager.widget.PagerAdapter
        public Parcelable saveState() {
            return null;
        }

        @Override // androidx.viewpager.widget.PagerAdapter
        public void unregisterDataSetObserver(DataSetObserver observer) {
            if (observer != null) {
                super.unregisterDataSetObserver(observer);
            }
        }
    }
}
