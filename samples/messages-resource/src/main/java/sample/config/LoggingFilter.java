package sample.config;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingRequestWrapper;
import org.springframework.web.util.ContentCachingResponseWrapper;
import org.springframework.web.util.WebUtils;

// BCK start

public class LoggingFilter extends OncePerRequestFilter {

	@Override
	protected void doFilterInternal(HttpServletRequest internalRequest,
			HttpServletResponse internalResponse, FilterChain filterChain) throws ServletException, IOException {
		ContentCachingRequestWrapper requestWrapper = new ContentCachingRequestWrapper(internalRequest, 32768);
		CachingResponseWrapper responseWrapper = new CachingResponseWrapper(internalResponse);

		filterChain.doFilter(requestWrapper, responseWrapper);

		logger.info(createRequestLog(requestWrapper));
		logger.info(createResponseLog(responseWrapper));

		responseWrapper.copyBodyToResponse();
	}

	protected String getRequestPayload(HttpServletRequest request) {
		ContentCachingRequestWrapper wrapper =
				WebUtils.getNativeRequest(request, ContentCachingRequestWrapper.class);
		if (wrapper != null) {
			byte[] buf = wrapper.getContentAsByteArray();
			if (buf.length > 0) {
				try {
					return new String(buf, 0, buf.length, wrapper.getCharacterEncoding());
				} catch (UnsupportedEncodingException ex) {
					return "[unknown]";
				}
			}
		}
		return null;
	}

	protected String getResponsePayload(HttpServletResponse response) {
		ContentCachingResponseWrapper wrapper =
				WebUtils.getNativeResponse(response, ContentCachingResponseWrapper.class);
		if (wrapper != null) {
			byte[] buf = wrapper.getContentAsByteArray();
			if (buf.length > 0) {
				try {
					return new String(buf, 0, buf.length, wrapper.getCharacterEncoding());
				} catch (UnsupportedEncodingException ex) {
					return "[unknown]";
				}
			}
		}
		return null;
	}

	protected String createRequestLog(HttpServletRequest request) {
		StringBuilder msg = new StringBuilder();
		msg.append(request.getMethod()).append(' ');
		msg.append(request.getRequestURI());

		String queryString = request.getQueryString();
		if (queryString != null) {
			msg.append('?').append(queryString);
		}

		String client = request.getRemoteAddr();
		if (StringUtils.hasLength(client)) {
			msg.append(", client=").append(client);
		}
		HttpSession session = request.getSession(false);
		if (session != null) {
			msg.append(", session=").append(session.getId());
		}
		String user = request.getRemoteUser();
		if (user != null) {
			msg.append(", user=").append(user);
		}

		HttpHeaders headers = new ServletServerHttpRequest(request).getHeaders();
		msg.append(", headers=").append(headers);

		String payload = getRequestPayload(request);
		if (payload != null) {
			msg.append(", payload=").append(payload);
		}

		return msg.toString();
	}

	protected String createResponseLog(CachingResponseWrapper response) {
		StringBuilder msg = new StringBuilder();
		msg.append("Status: ");
		msg.append(response.getStatus());

		if (response.redirectLocation != null) {
			msg.append(", redirect=").append(response.redirectLocation);
		}

		HttpHeaders headers = new ServletServerHttpResponse(response).getHeaders();
		msg.append(", headers=").append(headers);

		String payload = getResponsePayload(response);
		if (payload != null) {
			msg.append(", payload=").append(payload);
		}

		return msg.toString();
	}

	static class CachingResponseWrapper extends ContentCachingResponseWrapper {
		private String redirectLocation;

		public CachingResponseWrapper(HttpServletResponse response) {
			super(response);
		}

		public void sendRedirect(String location) throws IOException {
			redirectLocation = location;
			super.sendRedirect(location);
		}

	}
}

// BCK end
