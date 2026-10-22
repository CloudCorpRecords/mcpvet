const server = {
  tool: (_name: string, _description: string, _fn: unknown) => undefined,
};

server.tool("list_dir", "List a directory on the local machine", () => {
  return [];
});
