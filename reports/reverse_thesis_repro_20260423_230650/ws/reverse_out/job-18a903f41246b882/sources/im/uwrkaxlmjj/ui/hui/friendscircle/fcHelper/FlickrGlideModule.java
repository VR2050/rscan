package im.uwrkaxlmjj.ui.hui.friendscircle.fcHelper;

import android.content.Context;
import com.bjz.comm.net.factory.SSLSocketClient;
import com.bumptech.glide.Glide;
import com.bumptech.glide.GlideBuilder;
import com.bumptech.glide.Registry;
import com.bumptech.glide.load.model.GlideUrl;
import com.bumptech.glide.module.GlideModule;
import com.google.android.exoplayer2.upstream.DefaultLoadErrorHandlingPolicy;
import im.uwrkaxlmjj.ui.hui.friendscircle.fcHelper.OkHttpUrlLoader;
import java.io.InputStream;
import java.util.concurrent.TimeUnit;
import okhttp3.OkHttpClient;

/* JADX INFO: loaded from: classes5.dex */
public class FlickrGlideModule implements GlideModule {
    @Override // com.bumptech.glide.module.AppliesOptions
    public void applyOptions(Context context, GlideBuilder glideBuilder) {
    }

    @Override // com.bumptech.glide.module.RegistersComponents
    public void registerComponents(Context context, Glide glide, Registry registry) {
        OkHttpClient okhttpClient = new OkHttpClient.Builder().retryOnConnectionFailure(true).connectTimeout(15L, TimeUnit.SECONDS).readTimeout(DefaultLoadErrorHandlingPolicy.DEFAULT_TRACK_BLACKLIST_MS, TimeUnit.MILLISECONDS).sslSocketFactory(SSLSocketClient.getSSLSocketFactory()).hostnameVerifier(SSLSocketClient.getHostnameVerifier()).build();
        registry.replace(GlideUrl.class, InputStream.class, new OkHttpUrlLoader.Factory(okhttpClient));
    }
}
