package com.bjz.comm.net.api;

import com.bjz.comm.net.bean.BResponse;
import com.bjz.comm.net.bean.FcMediaResponseBean;
import com.bjz.comm.net.bean.IPResponse;
import com.just.agentweb.AgentWebPermissions;
import io.reactivex.Observable;
import java.util.ArrayList;
import okhttp3.RequestBody;
import okhttp3.ResponseBody;
import retrofit2.http.Body;
import retrofit2.http.GET;
import retrofit2.http.Headers;
import retrofit2.http.POST;
import retrofit2.http.Query;
import retrofit2.http.Streaming;
import retrofit2.http.Url;

/* JADX INFO: loaded from: classes4.dex */
public interface ApiCommon {
    @Headers({"BaseUrl:self"})
    @Streaming
    @GET
    Observable<ResponseBody> downloadImg(@Url String str);

    @Headers({"BaseUrl:self"})
    @GET
    Observable<ResponseBody> getDiscoveryPageBannerData(@Url String str);

    @Headers({"BaseUrl:self"})
    @GET
    @Deprecated
    Observable<IPResponse> getIpLocation(@Url String str);

    @GET("basesvc/uploadurl")
    Observable<BResponse<ArrayList<String>>> getUploadAddr(@Query(AgentWebPermissions.ACTION_LOCATION) int i);

    @Headers({"BaseUrl:self"})
    @POST
    Observable<BResponse<FcMediaResponseBean>> uploadFile(@Url String str, @Body RequestBody requestBody);
}
