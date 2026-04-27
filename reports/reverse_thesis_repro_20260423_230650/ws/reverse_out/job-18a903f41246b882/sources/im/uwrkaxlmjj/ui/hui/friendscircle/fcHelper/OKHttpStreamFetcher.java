package im.uwrkaxlmjj.ui.hui.friendscircle.fcHelper;

import android.util.Log;
import com.bumptech.glide.Priority;
import com.bumptech.glide.load.DataSource;
import com.bumptech.glide.load.HttpException;
import com.bumptech.glide.load.data.DataFetcher;
import com.bumptech.glide.load.model.GlideUrl;
import com.bumptech.glide.util.ContentLengthInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Map;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.ResponseBody;

/* JADX INFO: loaded from: classes5.dex */
public class OKHttpStreamFetcher implements DataFetcher<InputStream> {
    private static final String TAG = "OkHttpFetcher";
    private volatile Call call;
    private final Call.Factory client;
    ResponseBody responseBody;
    InputStream stream;
    private final GlideUrl url;

    public OKHttpStreamFetcher(Call.Factory client, GlideUrl url) {
        this.client = client;
        this.url = url;
    }

    @Override // com.bumptech.glide.load.data.DataFetcher
    public void loadData(Priority priority, final DataFetcher.DataCallback<? super InputStream> callback) {
        Request.Builder requestBuilder = new Request.Builder().url(this.url.toStringUrl());
        for (Map.Entry<String, String> headerEntry : this.url.getHeaders().entrySet()) {
            String key = headerEntry.getKey();
            requestBuilder.addHeader(key, headerEntry.getValue());
        }
        Request request = requestBuilder.build();
        this.call = this.client.newCall(request);
        this.call.enqueue(new Callback() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle.fcHelper.OKHttpStreamFetcher.1
            @Override // okhttp3.Callback
            public void onFailure(Call call, IOException e) {
                if (Log.isLoggable(OKHttpStreamFetcher.TAG, 3)) {
                    Log.d(OKHttpStreamFetcher.TAG, "OkHttp failed to obtain result", e);
                }
                callback.onLoadFailed(e);
            }

            @Override // okhttp3.Callback
            public void onResponse(Call call, Response response) throws IOException {
                OKHttpStreamFetcher.this.responseBody = response.body();
                if (response.isSuccessful()) {
                    long contentLength = OKHttpStreamFetcher.this.responseBody.contentLength();
                    OKHttpStreamFetcher oKHttpStreamFetcher = OKHttpStreamFetcher.this;
                    oKHttpStreamFetcher.stream = ContentLengthInputStream.obtain(oKHttpStreamFetcher.responseBody.byteStream(), contentLength);
                    callback.onDataReady(OKHttpStreamFetcher.this.stream);
                    return;
                }
                callback.onLoadFailed(new HttpException(response.message(), response.code()));
            }
        });
    }

    @Override // com.bumptech.glide.load.data.DataFetcher
    public void cleanup() {
        try {
            if (this.stream != null) {
                this.stream.close();
            }
        } catch (IOException e) {
        }
        ResponseBody responseBody = this.responseBody;
        if (responseBody != null) {
            responseBody.close();
        }
    }

    @Override // com.bumptech.glide.load.data.DataFetcher
    public void cancel() {
        Call local = this.call;
        if (local != null) {
            local.cancel();
        }
    }

    @Override // com.bumptech.glide.load.data.DataFetcher
    public Class<InputStream> getDataClass() {
        return InputStream.class;
    }

    @Override // com.bumptech.glide.load.data.DataFetcher
    public DataSource getDataSource() {
        return DataSource.REMOTE;
    }
}
