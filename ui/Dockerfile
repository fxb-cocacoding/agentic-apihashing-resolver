FROM node:24-alpine

WORKDIR /app/ui

RUN addgroup -S appgroup \
    && adduser -S appuser -G appgroup -h /home/appuser \
    && mkdir -p /home/appuser/.npm /app/ui \
    && chown -R appuser:appgroup /home/appuser /app

COPY ui/package.json ui/package-lock.json ./
RUN npm install \
    && chown -R appuser:appgroup /app /home/appuser

COPY ui ./
RUN chown -R appuser:appgroup /app /home/appuser

USER appuser

CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0", "--port", "5173"]
