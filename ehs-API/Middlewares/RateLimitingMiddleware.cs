using System.Collections.Concurrent;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System;

namespace ehs_API.Middlewares
{
    public class RateLimitingMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<RateLimitingMiddleware> _logger;
        private readonly ConcurrentDictionary<string, RequestCounter> _requestCounters = new ConcurrentDictionary<string, RequestCounter>();
        private readonly int _requestLimit = 100; // Maximum requests allowed
        private readonly TimeSpan _timeWindow = TimeSpan.FromMinutes(1); // Time window for rate limiting

        public RateLimitingMiddleware(RequestDelegate next, ILogger<RateLimitingMiddleware> logger)
        {
            _next = next;
            _logger = logger;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            var ipAddress = context.Connection.RemoteIpAddress.ToString();
            var currentTime = DateTime.UtcNow;

            var requestCounter = _requestCounters.GetOrAdd(ipAddress, _ => new RequestCounter { StartTime = currentTime });

            // Update the request counter
            if (currentTime - requestCounter.StartTime > _timeWindow)
            {
                requestCounter.Requests = 1;
                requestCounter.StartTime = currentTime;
            }
            else
            {
                requestCounter.Requests++;
            }

            if (requestCounter.Requests > _requestLimit)
            {
                _logger.LogWarning("Rate limit exceeded for IP: {IpAddress}", ipAddress);
                context.Response.StatusCode = StatusCodes.Status429TooManyRequests;
                await context.Response.WriteAsync("Too many requests. Please try again later.");
                return;
            }

            await _next(context);
        }

        private class RequestCounter
        {
            public DateTime StartTime { get; set; }
            public int Requests { get; set; }
        }
    }
}
